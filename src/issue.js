import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020'
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey'
import { CryptoLD } from 'crypto-ld'
import { driver as keyDriver } from '@digitalbazaar/did-method-key'
import { driver as webDriver } from '@interop/did-web-resolver'
import { securityLoader } from '@digitalcredentials/security-document-loader'
import { getTenantSeed } from './config.js'
import SigningException from './SigningException.js'
import { issue as signVC } from '@digitalbazaar/vc'
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey'
import * as Ed25519Signature2020Suite from './suites/Ed25519Signature2020Suite.js'
import * as EddsaRdfc2022Suite from './suites/EddsaRdfc2022Suite.js'
import * as EcdsaRdfc2019Suite from './suites/EcdsaRdfc2019Suite.js'

/** P-256 curve name used for every ecdsa-rdfc-2019 key this service mints. */
const ECDSA_CURVE = 'P-256'

let ISSUER_INSTANCES = {}
const documentLoader = securityLoader().build()

// Crypto library for linked data
const cryptoLd = new CryptoLD()
cryptoLd.use(Ed25519VerificationKey2020)

// DID drivers
const didWebDriver = webDriver({ cryptoLd })
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
  if (!config?.didSeed) throw new SigningException(404, "Tenant doesn't exist.")

  const { didSeed, didMethod, didUrl, cryptosuite } = config
  // Include cryptosuite in cache key to handle tenants with different suites
  const cacheKey = `${instanceId}:${cryptosuite || 'legacy'}`

  if (!ISSUER_INSTANCES[cacheKey]) {
    ISSUER_INSTANCES[cacheKey] = await buildIssuerInstance(
      didSeed,
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
 * Selects the appropriate suite module based on cryptosuite configuration.
 *
 * @param {string} cryptosuite - The cryptosuite name (e.g., 'eddsa-rdfc-2022')
 * @returns {object} The suite module
 */
const selectSuite = (cryptosuite) => {
  switch (cryptosuite) {
    case 'eddsa-rdfc-2022':
      return EddsaRdfc2022Suite
    case 'ecdsa-rdfc-2019':
      return EcdsaRdfc2019Suite
    default:
      // Default to legacy Ed25519Signature2020
      return Ed25519Signature2020Suite
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

const buildIssuerInstance = async (seed, method, url, cryptosuite) => {
  const { didDocument, key } = await getSigningMaterial({
    seed,
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

export async function getSigningMaterial({ method, seed, url, cryptosuite }) {
  let did, key

  // ECDSA needs a genuine P-256 key, not an Ed25519 one — a different curve,
  // not a different wrapper around the same key. It is therefore generated
  // here rather than derived from the Ed25519 material the other suites use,
  // and both DID methods are served from the one branch.
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
      throw new SigningException(
        400,
        'ecdsa-rdfc-2019 is supported for did:key only. The did:web driver cannot express a P-256 verification method, and issuing one would publish a DID document that misdescribes the key.'
      )
    }
    const keyPair = await EcdsaMultikey.generate({ curve: ECDSA_CURVE, seed })
    did = await didKeyDriver.fromKeyPair({ verificationKeyPair: keyPair })
    const assertionMethod = did.methodFor({ purpose: 'assertionMethod' })
    key = await EcdsaMultikey.from({
      type: 'Multikey',
      id: assertionMethod.id,
      controller: assertionMethod.controller,
      publicKeyMultibase: assertionMethod.publicKeyMultibase,
      secretKeyMultibase: keyPair.secretKeyMultibase
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
