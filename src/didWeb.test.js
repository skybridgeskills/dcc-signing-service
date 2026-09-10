import { expect } from 'chai'
import { normaliseDidDocument } from './didWeb.js'
import * as Ed25519Signature2020Suite from './suites/Ed25519Signature2020Suite.js'

/**
 * Unit tests for the normaliser itself.
 *
 * The end-to-end shape is asserted through the endpoint in `app.test.js`. What
 * cannot be reached from there is the failure branch: the endpoint only ever
 * sees the driver's real output, so the one case that matters most — a driver
 * whose output shape has changed — has to be constructed by hand.
 */
describe('normaliseDidDocument', () => {
  const did = 'did:web:example.com:ui:x'
  const key = 'z6MkfGZKFTyxiH9HgFUHbPQigEWh8PtFaRkESt9oQLiTvhVq'

  // The shape `@interop/did-web-resolver@5.0.0` returns for a seeded generate:
  // one embedded method, no `verificationMethod`, and an x25519 context it
  // never backs with a `keyAgreement` key.
  const driverOutput = () => ({
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
      'https://w3id.org/security/suites/x25519-2020/v1'
    ],
    id: did,
    assertionMethod: [
      {
        id: `${did}#${key}`,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: key
      }
    ]
  })

  it('moves the driver’s method without altering its values', () => {
    const input = driverOutput()
    const normalised = normaliseDidDocument(input, Ed25519Signature2020Suite)

    expect(normalised.verificationMethod).to.eql([
      {
        id: `${did}#${key}`,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: key
      }
    ])
    expect(normalised.assertionMethod).to.eql([`${did}#${key}`])
    expect(normalised.authentication).to.eql([`${did}#${key}`])
    expect(normalised.id).to.eql(did)
    // A re-expression, not a rewrite: the input is left alone.
    expect(input).to.eql(driverOutput())
  })

  it('throws rather than publishing a document with no key', () => {
    // A driver upgrade that stopped embedding the method would, under any
    // silent fallback, serve a key-less document that still looks like a DID
    // document. Failing loudly is the point.
    for (const broken of [
      { id: did },
      { id: did, assertionMethod: [] },
      { id: did, assertionMethod: [`${did}#${key}`] }
    ]) {
      let error
      try {
        normaliseDidDocument(broken, Ed25519Signature2020Suite)
      } catch (e) {
        error = e
      }
      expect(error, `expected ${JSON.stringify(broken)} to be refused`).to.exist
      expect(error.code).to.eql(500)
      expect(error.message).to.match(/output shape has changed/)
    }
  })
})
