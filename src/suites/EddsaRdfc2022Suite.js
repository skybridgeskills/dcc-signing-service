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
