import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020'
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey'
import { driver as keyDriver } from '@digitalbazaar/did-method-key'
import { securityLoader } from '@digitalcredentials/security-document-loader'
import { getTenantSeed } from './config.js'
import { didWebDriver, ECDSA_DID_WEB_REFUSAL } from './didWeb.js'
import SigningException from './SigningException.js'
import { addPinnedContexts } from './contexts/index.js'
import { issue as signVC } from '@digitalbazaar/vc'
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey'
import selectSuite from './suites/selectSuite.js'
import {
  assertKeyMaterialMatchesCryptosuite,
  loadEcdsaKeyPair
} from './keyMaterial.js'

let ISSUER_INSTANCES = {}

// The one document loader signing uses. It resolves contexts from memory only:
// `securityLoader()`'s bundled set plus the contexts pinned in `src/contexts/`.
// `fetchRemoteContexts` stays off on purpose — signing performs no network
// request for a context, so the bytes a signature covers are the bytes that
// were reviewed. See docs/adr/2026-09-29-signing-pins-jsonld-contexts.md
// before changing this, and add a context to `src/contexts/` rather than
// turning fetching on.
const documentLoader = addPinnedContexts(securityLoader()).build()

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

/**
 * Fails loudly, by name, when a credential carries a context this service
 * cannot serve.
 *
 * WHY THIS EXISTS. `jsonld` wraps the document loader's own error in a fixed
 * message that names no URL and lists four causes, none of which is the real
 * one (`ContextResolver._fetchContext`, `jsonld/lib/ContextResolver.js:173`).
 * The URL survives only in the error's `details`, which neither its message
 * nor its stack carries — and those two are all `errorLogger` writes. That
 * message reached an operator as
 * "Dereferencing a URL did not result in a valid JSON-LD object" for
 * `https://w3id.org/identification/v1rc1` — a context that was reachable,
 * valid and simply not pinned here — and the URL it wanted was in the error
 * one frame below.
 *
 * This service signs from a closed set of contexts (see `src/contexts/` and
 * the ADR), so "which URL" is always answerable before canonization starts,
 * by asking the loader directly rather than relying on the shape of
 * `jsonld`'s error. It
 * costs one loader lookup per context per request, all from memory. Only the
 * top-level `@context` is probed; scoped contexts inside a pinned document are
 * part of that document and reviewed with it.
 *
 * STATUS 400, deliberately. The credential as sent cannot be signed by this
 * service, and resending it unchanged will fail identically — so not a 5xx,
 * which tells a caller the fault is transient and worth retrying. 400 matches
 * the other refusals of a credential's shape (the empty-body guards in
 * `app.js`, the ecdsa-rdfc-2019 did:web refusal) rather than the 420 that
 * `addIssuerId` uses, which is not a registered status. The remedy may be ours
 * (pin the context) rather than the caller's; the message says so.
 *
 * @param {object} credential - After `injectContexts`, so the suite's own
 *   required contexts are probed too.
 * @param {Function} documentLoader
 */
const assertContextsResolvable = async (credential, documentLoader) => {
  const contexts = Array.isArray(credential['@context'])
    ? credential['@context']
    : [credential['@context']]
  for (const entry of contexts) {
    // An inline context object is legal and needs no dereference.
    if (typeof entry !== 'string') continue
    try {
      await documentLoader(entry)
    } catch (e) {
      // The loader's own error ("Document not found in document loader: <url>")
      // is kept as the stack, which `errorLogger` writes to the log.
      throw new SigningException(
        400,
        `Cannot sign: the JSON-LD context ${entry} is not available to this ` +
          `service. Signing resolves contexts locally and never fetches them; ` +
          `pin it in src/contexts/ to sign credentials that use it.`,
        e?.stack
      )
    }
  }
}

/**
 * Turns `jsonld`'s safe-mode failure into a refusal that names what it refused.
 *
 * WHY THIS EXISTS. Canonization runs in safe mode, which refuses to sign a
 * credential any part of which would be silently dropped — correctly, since a
 * dropped property is in the JSON but not under the signature. Until the
 * loader carried the final VC 2.0 context, an undefined property was never
 * dropped: the pre-Recommendation copy declared an `@vocab`
 * (`…/credentials/issuer-dependent#`) that caught every such term. The final
 * context has no `@vocab`, so a property no context defines now fails here —
 * and `jsonld` reports it as a bare "Safe mode validation error." that
 * reached callers as a 500 naming nothing. The property is in the error's
 * `details`; this puts it in the message.
 *
 * 400, like the context refusal: the credential as sent cannot be signed and
 * resending it will fail the same way. The author's remedy is to define the
 * term — a context that defines it, or an inline `{ "@vocab": … }`.
 *
 * @param {Error} e - Whatever signing threw.
 * @returns {SigningException|undefined} The refusal, or undefined when `e` is
 *   not a safe-mode failure and should propagate unchanged.
 */
const safeModeRefusal = (e) => {
  if (e?.name !== 'jsonld.ValidationError') return undefined
  const event = e.details?.event
  const property = event?.details?.property
  const message = property
    ? `Cannot sign: the property "${property}" is not defined by any of the ` +
      `credential's JSON-LD contexts, so it would not be covered by the ` +
      `signature. Add a context that defines it, or an inline @vocab.`
    : `Cannot sign: JSON-LD safe mode refused the credential ` +
      `(${event?.code ?? 'unknown'}: ${event?.message ?? e.message}).`
  return new SigningException(400, message, e.stack)
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
    await assertContextsResolvable(credCopy, this.documentLoader)
    try {
      // `await`, not a bare `return`: without it the rejection bypasses this
      // catch entirely, which it did until the safe-mode refusal below
      // needed it.
      return await signVC({
        credential: credCopy,
        suite: this.signingSuite,
        documentLoader: this.documentLoader,
        ...options
      })
    } catch (e) {
      const refusal = safeModeRefusal(e)
      if (refusal) throw refusal
      console.error(e)
      throw e
    }
  }
}

export default issue
