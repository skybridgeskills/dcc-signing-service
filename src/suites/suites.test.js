import { expect } from 'chai'
import * as Ed25519Signature2020Suite from './Ed25519Signature2020Suite.js'
import * as EddsaRdfc2022Suite from './EddsaRdfc2022Suite.js'
import * as EcdsaRdfc2019Suite from './EcdsaRdfc2019Suite.js'
import { getSigningMaterial } from '../issue.js'
import { generateEcdsaKeyMaterial } from '../keyMaterial.js'

describe('Suites', () => {
  describe('Ed25519Signature2020Suite', () => {
    describe('getRequiredContexts', () => {
      it('returns the ed25519-2020 suite context URL', () => {
        const contexts = Ed25519Signature2020Suite.getRequiredContexts()

        expect(contexts).to.be.an('array')
        expect(contexts).to.have.length(1)
        expect(contexts[0]).to.eql(
          'https://w3id.org/security/suites/ed25519-2020/v1'
        )
      })
    })

    describe('getProofType', () => {
      it('returns Ed25519Signature2020 proof type', () => {
        const proofType = Ed25519Signature2020Suite.getProofType()

        expect(proofType).to.eql('Ed25519Signature2020')
      })
    })

    describe('DID document facts', () => {
      it('types a published verification method Ed25519VerificationKey2020', () => {
        expect(Ed25519Signature2020Suite.getVerificationMethodType()).to.eql(
          'Ed25519VerificationKey2020'
        )
        expect(Ed25519Signature2020Suite.getDidDocumentContext()).to.eql(
          'https://w3id.org/security/suites/ed25519-2020/v1'
        )
      })
    })
  })

  describe('EddsaRdfc2022Suite', () => {
    describe('getRequiredContexts', () => {
      it('returns the Data Integrity v2 context URLs', () => {
        const contexts = EddsaRdfc2022Suite.getRequiredContexts()

        expect(contexts).to.be.an('array')
        expect(contexts).to.have.length(2)
        expect(contexts[0]).to.eql('https://www.w3.org/ns/credentials/v2')
        expect(contexts[1]).to.eql(
          'https://w3id.org/security/data-integrity/v2'
        )
      })
    })

    describe('getProofType', () => {
      it('returns DataIntegrityProof proof type', () => {
        const proofType = EddsaRdfc2022Suite.getProofType()

        expect(proofType).to.eql('DataIntegrityProof')
      })
    })

    describe('DID document facts', () => {
      it('types a published verification method Multikey', () => {
        expect(EddsaRdfc2022Suite.getVerificationMethodType()).to.eql(
          'Multikey'
        )
        expect(EddsaRdfc2022Suite.getDidDocumentContext()).to.eql(
          'https://w3id.org/security/multikey/v1'
        )
      })

      it('does not return a credential context', () => {
        // The trap this pair exists to avoid: `getRequiredContexts` returns
        // *credential* contexts and has nothing to do with a DID document.
        expect(EddsaRdfc2022Suite.getRequiredContexts()).to.not.include(
          EddsaRdfc2022Suite.getDidDocumentContext()
        )
      })
    })
  })
})

describe('EcdsaRdfc2019Suite', () => {
  describe('getRequiredContexts', () => {
    it('returns the Data Integrity v2 context URLs', () => {
      const contexts = EcdsaRdfc2019Suite.getRequiredContexts()
      expect(contexts).to.include('https://w3id.org/security/data-integrity/v2')
    })
  })

  describe('getProofType', () => {
    it('returns DataIntegrityProof proof type', () => {
      expect(EcdsaRdfc2019Suite.getProofType()).to.equal('DataIntegrityProof')
    })
  })
})

describe('ecdsa-rdfc-2019 signing material', () => {
  // Minted key material, not a seed: `EcdsaMultikey.generate` discards a seed,
  // so P-256 material is persisted as both multibase halves. `keyMaterial.js`
  // has the argument; `keyMaterial.test.js` asserts the round trip.
  let keyMaterial

  before(async () => {
    keyMaterial = await generateEcdsaKeyMaterial()
  })

  it('mints a P-256 did:key, not an Ed25519 one', async () => {
    const { didDocument, key } = await getSigningMaterial({
      method: 'key',
      keyMaterial,
      cryptosuite: 'ecdsa-rdfc-2019'
    })
    // P-256 did:key carries the `zDna` multibase header; Ed25519 carries `z6Mk`.
    expect(didDocument.id).to.match(/^did:key:zDna/)
    expect(key.signer().algorithm).to.equal('P-256')
  })

  it('refuses did:web rather than publishing a misdescribed key', async () => {
    // The did:web driver composes an Ed25519/X25519-context document and emits
    // no verification method for an ECDSA key. Failing loudly is the point.
    let error
    try {
      await getSigningMaterial({
        method: 'web',
        keyMaterial,
        url: 'https://example.com/issuers/ecdsa',
        cryptosuite: 'ecdsa-rdfc-2019'
      })
    } catch (e) {
      error = e
    }
    expect(error, 'expected did:web + ecdsa-rdfc-2019 to be refused').to.exist
    expect(error.message).to.match(/did:key only/)
  })
})
