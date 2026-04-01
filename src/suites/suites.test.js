import { expect } from 'chai'
import * as Ed25519Signature2020Suite from './Ed25519Signature2020Suite.js'
import * as EddsaRdfc2022Suite from './EddsaRdfc2022Suite.js'

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
  })
})
