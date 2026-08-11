import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020'
import { CryptoLD } from 'crypto-ld'
import { driver as webDriver } from '@interop/did-web-resolver'
import { getTenantSeed } from './config.js'
import selectSuite from './suites/selectSuite.js'
import SigningException from './SigningException.js'

/**
 * The one did:web driver in this service.
 *
 * There used to be two — `generate.js:10` and `issue.js:26` each built their
 * own `webDriver({ cryptoLd })` — and a third was about to appear for the
 * document endpoint below. Two independently-constructed drivers can be
 * configured differently without anything failing loudly, and this module
 * exists precisely so a published DID document cannot disagree with the key
 * that signs. A single instance removes the only way that could happen inside
 * this process.
 */
const cryptoLd = new CryptoLD()
cryptoLd.use(Ed25519VerificationKey2020)

export const didWebDriver = webDriver({ cryptoLd })

/**
 * The refusal message for `ecdsa-rdfc-2019` + `did:web`.
 *
 * Shared verbatim between `getSigningMaterial` (which refuses to sign) and
 * `getTenantDidDocument` (which refuses to publish) so the two cannot drift
 * into disagreeing about whether that combination exists. See the long comment
 * at the throw site in `issue.js`.
 */
export const ECDSA_DID_WEB_REFUSAL =
  'ecdsa-rdfc-2019 is supported for did:key only. The did:web driver cannot express a P-256 verification method, and issuing one would publish a DID document that misdescribes the key.'

/** The context every DID document declares, first, per DID Core. */
const DID_CORE_CONTEXT = 'https://www.w3.org/ns/did/v1'

/**
 * Re-express the driver's DID document in the conventional shape.
 *
 * `@interop/did-web-resolver@5.0.0` embeds the whole verification method inside
 * `assertionMethod` and never emits a top-level `verificationMethod` array. Two
 * of its behaviours combine to get us there: passing a `seed` collapses its
 * five-purpose default key map to `{ assertionMethod: keyPair }`, and `initKeys`
 * always embeds the exported method into the relationship array. Deterministic
 * seed-based generation — exactly what this service does, and what the
 * anti-drift property below depends on — takes that path.
 *
 * The embedded form is *legal*: DID Core 1.0 §5.3.1 permits a verification
 * relationship's value to be either a DID URL or an embedded method map. So
 * this is an interop-robustness defect, not a spec violation — which is the
 * whole reason to fix it. A wallet that rejects the embedded form is not wrong,
 * and this service's job is to make a wallet's failure attributable to the
 * wallet. It is also not the shape our own `did:key` documents take, which is
 * how the campaign ended up with two hand-maintained copies of one tenant's
 * document and, through them, gap H1.
 *
 * This MOVES the method the driver already produced. It never builds one from
 * key material, because a document composed beside the signing path is exactly
 * the drift this module exists to make impossible. The only value it does not
 * carry through verbatim is the method's `type`, which is set from the tenant's
 * configured suite — see the ADR for why that is a deliberate, and accepted,
 * dependency on configuration.
 *
 * @param {object} didDocument - The document `didWebDriver.generate()` returned.
 * @param {object} suiteModule - The tenant's suite module, from `selectSuite`.
 * @returns {object} A new document; the input is not mutated.
 * @throws {SigningException} 500 if the driver's output is not the shape this
 *   function knows how to re-express.
 */
export function normaliseDidDocument(didDocument, suiteModule) {
  const embedded = didDocument?.assertionMethod?.[0]

  // Loud rather than lenient. A driver upgrade that changed this shape would,
  // under any silent fallback, publish a document with no usable key in it —
  // the same "issuer says one thing, key says another" failure this module was
  // written to close, arrived at by a different route. Better a 500 nobody can
  // miss than a 200 nobody checks.
  if (!embedded || typeof embedded !== 'object' || !embedded.id) {
    throw new SigningException(
      500,
      'The did:web driver returned a DID document with no embedded assertionMethod verification method. Its output shape has changed and the normaliser in didWeb.js needs updating.'
    )
  }

  return {
    '@context': [DID_CORE_CONTEXT, suiteModule.getDidDocumentContext()],
    id: didDocument.id,
    verificationMethod: [
      {
        id: embedded.id,
        // The one substitution: the type names the suite the tenant signs
        // with. `id`, `controller` and `publicKeyMultibase` are the driver's
        // own bytes, untouched — in particular the `#fragment` in `id`, which
        // is what `proof.verificationMethod` on an issued credential points at.
        type: suiteModule.getVerificationMethodType(),
        controller: embedded.controller,
        publicKeyMultibase: embedded.publicKeyMultibase
      }
    ],
    // References, not embeds. `authentication` is free and keeps the document
    // consistent with the `did:key` documents this service also produces.
    // `capabilityInvocation` / `capabilityDelegation` are omitted: an issuer
    // has no use for them and an unused relationship is one more thing a
    // reader has to decide whether to trust.
    assertionMethod: [embedded.id],
    authentication: [embedded.id]
  }
}

/**
 * Derive a tenant's `did:web` document from its configured seed and URL.
 *
 * **Derived, never stored.** The whole point of this function is that it makes
 * the same `didWebDriver.generate({ seed, url })` call the signing path makes
 * at `issue.js:196`, from the same `DID_SEEDS` entry — so the document that
 * gets published *is* the signing key's document rather than a copy of it.
 *
 * This exists because of gap H1: a hand-maintained DID document said one thing
 * while the configured seed produced another, the issuer identifier and the
 * signing key disagreed, and it went unnoticed through an entire milestone
 * because nothing ever compared them. A copy — in a repo file, in an env var,
 * anywhere — reintroduces that failure. There is deliberately no way to
 * override the returned document.
 *
 * @param {string} instanceId - Tenant / issuer instance name.
 * @returns {Promise<object>} The DID document, ready to serve as-is.
 * @throws {SigningException} 404 if the tenant is unknown or is not a did:web
 *   tenant; 400 for the refused `ecdsa-rdfc-2019` + `did:web` combination;
 *   500 if a did:web tenant has no `TENANT_DID_URL_<TENANT>`.
 */
export async function getTenantDidDocument(instanceId) {
  const config = await getTenantSeed(instanceId)
  if (!config?.didSeed) throw new SigningException(404, "Tenant doesn't exist.")

  const { didSeed, didMethod, didUrl, cryptosuite } = config

  if (didMethod !== 'web') {
    // A did:key tenant has no document to publish at a URL — its document is
    // recoverable from the identifier itself, so there is nothing to host.
    //
    // Not an information leak worth guarding: the caller already supplied the
    // tenant name in the URL, so a 404 tells them nothing they did not know
    // when they typed it. Distinguishing "no such tenant" from "not a web
    // tenant" in the message would, so both say the same thing.
    throw new SigningException(
      404,
      `No did:web document for '${instanceId}': this tenant is not configured with TENANT_DIDMETHOD_${instanceId.toUpperCase()}=web.`
    )
  }

  if (cryptosuite === 'ecdsa-rdfc-2019') {
    // `getSigningMaterial` refuses this combination, so such a tenant cannot
    // sign anything at all. Publishing an Ed25519 document for it would put a
    // key on the wire that never issues a credential — the same class of
    // "issuer says one thing, key says another" this module exists to prevent,
    // arrived at from the other direction. Refuse identically.
    throw new SigningException(400, ECDSA_DID_WEB_REFUSAL)
  }

  if (!didUrl) {
    throw new SigningException(
      500,
      `Tenant '${instanceId}' is configured as did:web but has no TENANT_DID_URL_${instanceId.toUpperCase()}.`
    )
  }

  const { didDocument } = await didWebDriver.generate({
    seed: didSeed,
    url: didUrl
  })
  // Normalised here, inside the one function the endpoint calls, so there is no
  // path that serves the driver's raw output.
  return normaliseDidDocument(didDocument, selectSuite(cryptosuite))
}
