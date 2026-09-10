import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020'
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey'
import { driver as keyDriver } from '@digitalbazaar/did-method-key'
import { securityLoader } from '@digitalcredentials/security-document-loader'
import { getTenantSeed } from './config.js'
import { didWebDriver, ECDSA_DID_WEB_REFUSAL } from './didWeb.js'
import SigningException from './SigningException.js'
import { issue as signVC } from '@digitalbazaar/vc'
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey'
import selectSuite from './suites/selectSuite.js'
import {
  assertKeyMaterialMatchesCryptosuite,
  loadEcdsaKeyPair
} from './keyMaterial.js'

let ISSUER_INSTANCES = {}
const documentLoader = securityLoader().build()

// DID drivers. `didWebDriver` is shared with `generate.js` and with the
// `GET /instance/:instanceId/did.json` endpoint — the published document has to
// come off the same driver as the signing key, or it is a copy again.
const didKeyDriver = keyDriver()

didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519VerificationKey2020.from
})

// P-256 multikeys carry the `zDna` header. Without this the did:key driver
// cannot express an ECDSA key at all, so ecdsa-rdfc-2019 could be selected
// as a suite but never produce a usable issuer DID.
didKeyDriver.use({
  multibaseMultikeyHeader: 'zDna',
  fromMultibase: EcdsaMultikey.from
})

/* FOR TESTING */
export const clearIssuerInstances = () => {
  ISSUER_INSTANCES = {}
}

const getIssuerInstance = async (instanceId) => {
  const config = await getTenantSeed(instanceId)
  // Existence is `keyMaterial`, not `didSeed`: an ecdsa-rdfc-2019 tenant has no
  // seed at all, and testing for one made it look like no tenant.
  if (!config?.keyMaterial)
    throw new SigningException(404, "Tenant doesn't exist.")

  const { keyMaterial, didMethod, didUrl, cryptosuite } = config
  // Include cryptosuite in cache key to handle tenants with different suites
  const cacheKey = `${instanceId}:${cryptosuite || 'legacy'}`

  if (!ISSUER_INSTANCES[cacheKey]) {
    ISSUER_INSTANCES[cacheKey] = await buildIssuerInstance(
      keyMaterial,
      didMethod,
      didUrl,
      cryptosuite
    )
  }
  return ISSUER_INSTANCES[cacheKey]
}

const issue = async (unsignedVerifiableCredential, instanceId) => {
  const {
    issuerInstance,
    didDocument: { id: issuerId }
  } = await getIssuerInstance(instanceId)
  addIssuerId(unsignedVerifiableCredential, issuerId)
  const signedVerifiableCredential = await issuerInstance.issueCredential({
    credential: unsignedVerifiableCredential
  })
  return signedVerifiableCredential
}

const addIssuerId = (credential, issuerId) => {
  if (!credential.issuer) {
    throw new SigningException(
      420,
      'An issuer property, either string or object, must be present.'
    )
  } else if (Array.isArray(credential.issuer)) {
    throw new SigningException(
      420,
      'An issuer property cannot be an Array, only a string or object.'
    )
  } else if (typeof credential.issuer === 'string') {
    credential.issuer = issuerId
  } else if (typeof credential.issuer === 'object') {
    credential.issuer.id = issuerId
  } else {
    throw new SigningException(
      420,
      'The issuer property must be either a string or an object.'
    )
  }
}

/**
 * Injects any suite-required JSON-LD contexts into the credential, deduping
 * while preserving order and keeping caller-supplied contexts first.
 *
 * @param {object} credential - The credential to inject contexts into (mutated)
 * @param {string[]} requiredContexts - Context URLs the suite requires
 */
const injectContexts = (credential, requiredContexts) => {
  const existing = Array.isArray(credential['@context'])
    ? credential['@context']
    : credential['@context']
      ? [credential['@context']]
      : []
  const merged = [...existing]
  for (const ctx of requiredContexts) {
    if (!merged.includes(ctx)) merged.push(ctx)
  }
  credential['@context'] = merged
}

const buildIssuerInstance = async (keyMaterial, method, url, cryptosuite) => {
  const { didDocument, key } = await getSigningMaterial({
    keyMaterial,
    method,
    url,
    cryptosuite
  })
  const suiteModule = selectSuite(cryptosuite)
  const signingSuite = suiteModule.createSuite(key)
  const requiredContexts = suiteModule.getRequiredContexts()
  const issuerInstance = new IssuerInstance({
    documentLoader,
    signingSuite,
    requiredContexts
  })
  return { issuerInstance, didDocument }
}

/**
 * Derives a tenant's issuer DID and a usable signing key from its key material.
 *
 * @param {object} args
 * @param {string} args.method - `key` or `web`.
 * @param {object} args.keyMaterial - A member of the key material union; see
 *   `keyMaterial.js`. ⚠️ This used to be a bare `seed`, which an
 *   `ecdsa-rdfc-2019` tenant cannot supply meaningfully.
 * @param {string} [args.url] - Required for `did:web`.
 * @param {string} [args.cryptosuite] - `TENANT_CRYPTOSUITE_<T>`.
 */
export async function getSigningMaterial({
  method,
  keyMaterial,
  url,
  cryptosuite
}) {
  let did, key
  assertKeyMaterialMatchesCryptosuite(keyMaterial, cryptosuite)
  const seed = keyMaterial.seed

  // ECDSA needs a genuine P-256 key, not an Ed25519 one — a different curve,
  // not a different wrapper around the same key. It cannot be derived from a
  // seed at all (see `keyMaterial.js`), so it is loaded from the two multibase
  // halves minted once at provisioning time, and both DID methods are served
  // from the one branch.
  if (cryptosuite === 'ecdsa-rdfc-2019') {
    if (method === 'web') {
      // Deliberately refused rather than mis-issued. The did:web driver
      // composes a DID document whose @context is hardcoded to the Ed25519
      // and X25519 suite contexts, with no Multikey / data-integrity context,
      // and it does not emit a verification method for an ECDSA key at all.
      // Publishing a P-256 key inside an Ed25519-context document would be a
      // silent mis-issuance: it would look fine here and fail, or worse
      // verify ambiguously, at a relying party.
      //
      // Supporting it means composing the document ourselves or replacing the
      // resolver — a larger change than adding a cryptosuite, and out of
      // scope until something needs it. did:key + ecdsa-rdfc-2019 works.
      //
      // The message lives in `didWeb.js` because the document endpoint refuses
      // the same combination with the same words: a tenant that cannot sign
      // must not have a key published on its behalf either.
      throw new SigningException(400, ECDSA_DID_WEB_REFUSAL)
    }
    // ⚠️ This was `EcdsaMultikey.generate({ curve, seed })`, and that call is
    // why this milestone exists: the library destructures only
    // `{id, controller, curve, keyAgreement}`, so the seed was silently
    // discarded and every restart minted a new issuer identity. Loading the
    // persisted halves is what makes the DID stable.
    const keyPair = await loadEcdsaKeyPair(keyMaterial)
    did = await didKeyDriver.fromKeyPair({ verificationKeyPair: keyPair })
    const assertionMethod = did.methodFor({ purpose: 'assertionMethod' })
    key = await EcdsaMultikey.from({
      type: 'Multikey',
      id: assertionMethod.id,
      controller: assertionMethod.controller,
      publicKeyMultibase: assertionMethod.publicKeyMultibase,
      secretKeyMultibase: keyMaterial.secretKeyMultibase
    })
    return { didDocument: did.didDocument, key }
  }

  if (method === 'web') {
    did = await didWebDriver.generate({ seed, url })
    const assertionMethod = did.methodFor({ purpose: 'assertionMethod' })

    // For eddsa-rdfc-2022, we need an Ed25519Multikey signer — same as the
    // did:key branch below. The did:web driver hands back an
    // Ed25519VerificationKey2020, whose signer reports no `algorithm`, and
    // DataIntegrityProof rejects it with "The signer's algorithm 'undefined'
    // does not match the required algorithm for the cryptosuite 'Ed25519'".
    if (cryptosuite === 'eddsa-rdfc-2022') {
      key = await Ed25519Multikey.from({
        type: 'Multikey',
        id: assertionMethod.id,
        controller: assertionMethod.controller,
        publicKeyMultibase: assertionMethod.publicKeyMultibase,
        secretKeyMultibase: assertionMethod.privateKeyMultibase
      })
    } else {
      // Legacy Ed25519Signature2020 uses the key object directly
      key = assertionMethod
    }
  } else {
    const verificationKeyPair = await Ed25519VerificationKey2020.generate({
      seed
    })
    did = await didKeyDriver.fromKeyPair({ verificationKeyPair })
    const assertionMethod = did.methodFor({ purpose: 'assertionMethod' })

    // For eddsa-rdfc-2022, we need an Ed25519Multikey signer
    if (cryptosuite === 'eddsa-rdfc-2022') {
      // Import the existing key pair as Ed25519Multikey
      key = await Ed25519Multikey.from({
        type: 'Multikey',
        id: assertionMethod.id,
        controller: assertionMethod.controller,
        publicKeyMultibase: assertionMethod.publicKeyMultibase,
        secretKeyMultibase: verificationKeyPair.privateKeyMultibase
      })
    } else {
      // Legacy Ed25519Signature2020 uses the key object directly
      key = await Ed25519VerificationKey2020.from({
        type: assertionMethod.type,
        controller: assertionMethod.controller,
        id: assertionMethod.id,
        publicKeyMultibase: assertionMethod.publicKeyMultibase,
        privateKeyMultibase: verificationKeyPair.privateKeyMultibase
      })
    }
  }
  return { didDocument: did.didDocument, key }
}

export class IssuerInstance {
  constructor({ documentLoader, signingSuite, requiredContexts }) {
    this.documentLoader = documentLoader
    this.signingSuite = signingSuite
    this.requiredContexts = requiredContexts || []
  }
  async issueCredential({ credential, options }) {
    // this library attaches the signature on the original object, so make a copy
    const credCopy = JSON.parse(JSON.stringify(credential))
    injectContexts(credCopy, this.requiredContexts)
    try {
      return signVC({
        credential: credCopy,
        suite: this.signingSuite,
        documentLoader: this.documentLoader,
        ...options
      })
    } catch (e) {
      console.error(e)
      throw e
    }
  }
}

export default issue
