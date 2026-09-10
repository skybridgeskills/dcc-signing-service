import { DataIntegrityProof } from '@digitalbazaar/data-integrity'
import { cryptosuite as ecdsaRdfc2019Cryptosuite } from '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite'

/**
 * Creates a DataIntegrityProof signing suite with the ecdsa-rdfc-2019
 * cryptosuite (ECDSA over P-256).
 *
 * Why this exists alongside the EdDSA suites: wallets differ on which
 * curve they verify. A wallet that verifies only Ed25519 will reject a
 * well-formed P-256 presentation and vice versa, so a harness that can
 * only issue one of them cannot tell a capability gap from a defect.
 *
 * @param {object} key - The signing key (Multikey with P-256)
 * @returns {DataIntegrityProof} The signing suite
 */
export function createSuite(key) {
  return new DataIntegrityProof({
    signer: key.signer(),
    cryptosuite: ecdsaRdfc2019Cryptosuite
  })
}

/**
 * Returns the required JSON-LD context URLs for ecdsa-rdfc-2019.
 *
 * Identical to eddsa-rdfc-2022's: both are Data Integrity proofs and the
 * cryptosuite name travels in the proof, not in a suite-specific context.
 *
 * @returns {string[]} Array of context URLs
 */
export function getRequiredContexts() {
  return [
    'https://www.w3.org/ns/credentials/v2',
    'https://w3id.org/security/data-integrity/v2'
  ]
}

/**
 * Returns the proof type identifier for this suite.
 *
 * @returns {string} The proof type
 */
export function getProofType() {
  return 'DataIntegrityProof'
}

/**
 * Returns the verification method `type` a published DID document should give
 * the signing key when this suite is in use.
 *
 * Exported so the three suite modules present the same surface, but the
 * published-document path never reaches it: `ecdsa-rdfc-2019` + `did:web` is
 * refused before a suite is ever selected (`didWeb.js`, `issue.js`), and a
 * `did:key` tenant has no document to host. It is the honest answer if
 * something ever does ask.
 *
 * @returns {string} The verification method type
 */
export function getVerificationMethodType() {
  return 'Multikey'
}

/**
 * Returns the JSON-LD context that defines this suite's verification method
 * type, for inclusion in a published DID document (never in a credential).
 *
 * Same caveat as `getVerificationMethodType`: unreachable from the did:web
 * publication path, which refuses this suite.
 *
 * @returns {string} The DID document context URL
 */
export function getDidDocumentContext() {
  return 'https://w3id.org/security/multikey/v1'
}
