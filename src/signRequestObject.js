import { getTenantSeed } from './config.js'
import { getSigningMaterial } from './issue.js'
import { getTenantDidDocument } from './didWeb.js'
import SigningException from './SigningException.js'

/**
 * Sign an OID4VP authorization request object as a compact JWS.
 *
 * ## Why a non-credential signature lives in the signing service
 *
 * This service's job has been "sign credentials" until now, so signing
 * something that is not a credential deserves an argument rather than a shrug.
 *
 * OID4VP §5.9.3's `decentralized_identifier` Client Identifier Prefix requires
 * the JOSE `kid` to identify a key in the DID document's `verificationMethod`.
 * ⚠️ **This service is the only component that derives both the published
 * document and the signing key from one seed**, and `didWeb.js` exists for
 * precisely that invariant — *"a published DID document cannot disagree with
 * the key that signs"*.
 *
 * A key held in the verifier instead would reintroduce the two-drivers drift
 * across a *service* boundary: a distributed gap H1, the failure where a
 * hand-maintained document said one thing while the configured seed produced
 * another and nothing ever compared them. **This endpoint is that existing
 * invariant extended to a second signature type**, not a new responsibility.
 *
 * The rejected alternative — a local key behind the verifier's own `did:web` —
 * stays available if the round trip ever becomes the wrong shape. ⚠️ **The cost
 * is accepted knowingly:** one JWS per `request_uri` GET, at most one per
 * exchange, and the by-value arm never fetches at all.
 *
 * ## ⚠️ The algorithm is FORCED to EdDSA. It is not a choice.
 *
 * `ECDSA_DID_WEB_REFUSAL` says the `did:web` driver cannot express a P-256
 * verification method, so a `did:web` tenant signs Ed25519 and nothing else.
 *
 * ⚠️ **This has an interop consequence, and it must not be papered over here.**
 * ES256 is the de-facto default for OID4VP request-object signing in the
 * mDL/EUDI world, so a conformant signed arm may prove *less* interoperable
 * than the unsigned accommodation it is meant to replace. That is a thing to
 * measure, not to pre-empt: **do not add a P-256 path here.** It would be a new
 * key, a new document and a different decision.
 *
 * ## ⚠️ This is NOT the `alg: none` arm, and the two must never be confusable
 *
 * The verifier also serves an unsigned request object with an empty signature
 * segment, as a registered accommodation. That one is non-conformant and says
 * so. This one carries a real signature over a real key. A test asserts the
 * signature segment is non-empty for exactly this reason.
 */

const base64url = (input) => Buffer.from(input).toString('base64url')

/**
 * The JOSE header. `typ` mirrors the media type per RFC 9101 §10.8's
 * explicit-typing guidance, and `alg` is EdDSA because the DID method leaves no
 * other option.
 */
const headerFor = (kid) => ({ alg: 'EdDSA', typ: 'oauth-authz-req+jwt', kid })

/**
 * @param {object} claims - The authorization request object to sign. ⚠️ Signed
 *   as given: choosing the payload is the verifier's job, not this service's.
 * @param {string} instanceId - Tenant / issuer instance name.
 * @returns {Promise<string>} A compact JWS: `<header>.<payload>.<signature>`.
 * @throws {SigningException} 400 for an empty payload or a refused suite; 404
 *   for an unknown or non-`did:web` tenant; 500 if the tenant is misconfigured
 *   or the derived key cannot sign.
 */
export async function signRequestObject(claims, instanceId) {
  if (!claims || typeof claims !== 'object' || !Object.keys(claims).length) {
    throw new SigningException(
      400,
      'A request object must be provided in the body.'
    )
  }

  // ⚠️ THE ANTI-DRIFT MOVE, and the reason this endpoint is in this repo.
  //
  // The `kid` is read off the document the `did.json` endpoint publishes, by
  // calling the very same function — not rebuilt from `did + '#' + something`.
  // A composed `kid` is a second statement about which key signs, and a second
  // statement is the thing `didWeb.js` was written to make impossible.
  //
  // It also buys every refusal for free, with identical wording: unknown
  // tenant, non-did:web tenant, the ECDSA + did:web refusal, and a did:web
  // tenant with no URL all throw here, from the one place that already decides
  // them.
  const didDocument = await getTenantDidDocument(instanceId)
  const kid = didDocument?.verificationMethod?.[0]?.id
  if (!kid) {
    throw new SigningException(
      500,
      `The published DID document for '${instanceId}' has no verificationMethod id to use as a JOSE kid.`
    )
  }

  const { keyMaterial, didMethod, didUrl, cryptosuite } =
    await getTenantSeed(instanceId)
  const { key } = await getSigningMaterial({
    keyMaterial,
    method: didMethod,
    url: didUrl,
    cryptosuite
  })

  const signer = key?.signer?.()
  if (typeof signer?.sign !== 'function') {
    // Loud rather than lenient, per `normaliseDidDocument`: better a 500 nobody
    // can miss than a 200 nobody checks. There is deliberately no unsigned
    // fallback — an unsigned result from a "sign" endpoint is the worst
    // possible outcome, because it looks like success.
    throw new SigningException(
      500,
      `The signing key derived for '${instanceId}' exposes no signer; the key type returned by getSigningMaterial has changed.`
    )
  }

  const signingInput = `${base64url(JSON.stringify(headerFor(kid)))}.${base64url(
    JSON.stringify(claims)
  )}`
  const signature = await signer.sign({
    data: new TextEncoder().encode(signingInput)
  })

  return `${signingInput}.${base64url(signature)}`
}

/** The media type OID4VP §5.10.1 names for a request-object response. */
export const REQUEST_OBJECT_JWT_MEDIA_TYPE = 'application/oauth-authz-req+jwt'

export default signRequestObject
