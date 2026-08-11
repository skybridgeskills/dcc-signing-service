import * as Ed25519Signature2020Suite from './Ed25519Signature2020Suite.js'
import * as EddsaRdfc2022Suite from './EddsaRdfc2022Suite.js'
import * as EcdsaRdfc2019Suite from './EcdsaRdfc2019Suite.js'

/**
 * Selects the appropriate suite module based on cryptosuite configuration.
 *
 * This lived as a module-private const in `issue.js` until the published
 * `did:web` document needed the same mapping — the document's verification
 * method type has to name the suite the tenant actually signs with. `issue.js`
 * already imports `didWeb.js`, so having `didWeb.js` reach back into `issue.js`
 * for this would have created an import cycle. It lives here instead so both
 * sides import downwards and the cycle is unrepresentable rather than merely
 * avoided.
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

export default selectSuite
