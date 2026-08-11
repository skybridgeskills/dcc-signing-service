import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020'

/**
 * Creates an Ed25519Signature2020 signing suite.
 * This is the legacy cryptosuite that was used before DataIntegrityProof.
 *
 * @param {object} key - The signing key (Ed25519VerificationKey2020)
 * @returns {Ed25519Signature2020} The signing suite
 */
export function createSuite(key) {
  return new Ed25519Signature2020({ key })
}

/**
 * Returns the required JSON-LD context URLs for Ed25519Signature2020.
 *
 * @returns {string[]} Array of context URLs
 */
export function getRequiredContexts() {
  return ['https://w3id.org/security/suites/ed25519-2020/v1']
}

/**
 * Returns the proof type identifier for this suite.
 *
 * @returns {string} The proof type
 */
export function getProofType() {
  return 'Ed25519Signature2020'
}

/**
 * Returns the verification method `type` a published DID document should give
 * the signing key when this suite is in use.
 *
 * Distinct from `getRequiredContexts` on purpose: that one returns *credential*
 * contexts, and reusing it here would put credential vocabulary in a DID
 * document. See `getDidDocumentContext` below.
 *
 * @returns {string} The verification method type
 */
export function getVerificationMethodType() {
  return 'Ed25519VerificationKey2020'
}

/**
 * Returns the JSON-LD context that defines this suite's verification method
 * type, for inclusion in a published DID document (never in a credential).
 *
 * @returns {string} The DID document context URL
 */
export function getDidDocumentContext() {
  return 'https://w3id.org/security/suites/ed25519-2020/v1'
}
