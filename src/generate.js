import { generateSecretKeySeed } from 'bnid'
import decodeSeed from './utils/decodeSeed.js'
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020'

import { driver as keyDriver } from '@digitalbazaar/did-method-key'
// One driver for the whole service — see the comment in `didWeb.js`.
import { didWebDriver as didDriver, normaliseDidDocument } from './didWeb.js'
import selectSuite from './suites/selectSuite.js'

export default async function generateSeed({ url = false }) {
  const encodedSeed = await generateSecretKeySeed()
  const seed = await decodeSeed(encodedSeed)
  let didDocument
  if (url) {
    ;({ didDocument } = await didDriver.generate({ seed, url }))
    // Normalised through the same function as the published document, or this
    // endpoint becomes a second, disagreeing answer to "what does our did:web
    // document look like" — which is how the hand-copied documents got made.
    //
    // A generated seed has no tenant, so it has no configured cryptosuite:
    // this previews the *default* suite's shape (`Ed25519VerificationKey2020`).
    // A tenant configured with `TENANT_CRYPTOSUITE_<T>=eddsa-rdfc-2022` will
    // publish the same key with type `Multikey`; the key and the `#fragment`
    // are identical either way.
    didDocument = normaliseDidDocument(didDocument, selectSuite(undefined))
  } else {
    const didKeyDriver = keyDriver()
    didKeyDriver.use({
      multibaseMultikeyHeader: 'z6Mk',
      fromMultibase: Ed25519VerificationKey2020.from
    })
    const verificationKeyPair = await Ed25519VerificationKey2020.generate({
      seed
    })
    ;({ didDocument } = await didKeyDriver.fromKeyPair({ verificationKeyPair }))
  }
  const did = didDocument.id
  return { seed: encodedSeed, decodedSeed: seed, did, didDocument }
}
