import { DataIntegrityProof } from '@digitalbazaar/data-integrity'
import { cryptosuite as eddsaRdfc2022Cryptosuite } from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite'

/**
 * Creates a DataIntegrityProof signing suite with eddsa-rdfc-2022 cryptosuite.
 * This is the modern cryptosuite based on the Data Integrity specification.
 *
 * @param {object} key - The signing key (Multikey with Ed25519)
 * @returns {DataIntegrityProof} The signing suite
 */
export function createSuite(key) {
  return new DataIntegrityProof({
    signer: key.signer(),
    cryptosuite: eddsaRdfc2022Cryptosuite
  })
}

/**
 * Returns the required JSON-LD context URLs for eddsa-rdfc-2022.
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
 * A `DataIntegrityProof` verifier resolves the referenced method through
 * `Ed25519Multikey.from`, which expects `Multikey`. Our own verifier happens to
 * translate an `Ed25519VerificationKey2020` method for us — `toMultikey` falls
 * through for any non-`Multikey` type — but a third-party wallet is under no
 * obligation to, and this service exists to make a wallet's failure
 * attributable to the wallet.
 *
 * Distinct from `getRequiredContexts`, which returns *credential* contexts.
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
 * @returns {string} The DID document context URL
 */
export function getDidDocumentContext() {
  return 'https://w3id.org/security/multikey/v1'
}
