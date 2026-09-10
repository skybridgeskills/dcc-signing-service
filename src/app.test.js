import { driver } from '@digitalbazaar/did-method-key'
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020'
import decodeSeed from './utils/decodeSeed.js'
import { expect } from 'chai'
import request from 'supertest'
import { clearIssuerInstances, getSigningMaterial } from './issue.js'
import { ed25519SeedMaterial, generateEcdsaKeyMaterial } from './keyMaterial.js'
import {
  resetConfig,
  deleteSeed,
  TEST_TENANT_NAME,
  getTenantSeed
} from './config.js'
import {
  ed25519_2020suiteContext,
  getCredentialStatus,
  getCredentialStatusBitString,
  getUnsignedVC,
  getUnsignedVCWithStatus,
  getUnsignedVC2WithStatus,
  getUnsignedVCWithoutSuiteContext
} from './test-fixtures/vc.js'

import { build } from './app.js'

const didKeyDriver = driver()
didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519VerificationKey2020.from
})

let testDIDSeed
let didDocument
let verificationMethod
let signingDID
let app

describe('api', () => {
  before(async () => {
    testDIDSeed = await decodeSeed(process.env.TENANT_SEED_TESTING)
    const verificationKeyPair = await Ed25519VerificationKey2020.generate({
      seed: testDIDSeed
    })
    ;({ didDocument } = await didKeyDriver.fromKeyPair({ verificationKeyPair }))
    verificationMethod = didKeyDriver.publicMethodFor({
      didDocument,
      purpose: 'assertionMethod'
    }).id
    signingDID = didDocument.id
  })

  after(() => {})

  beforeEach(async () => {
    app = await build()
  })

  afterEach(async () => {})

  describe('GET /', () => {
    it('GET / => hello', (done) => {
      request(app)
        .get('/')
        .expect(200)
        .expect('Content-Type', /json/)
        .expect(/{"message":"signing-service server status: ok."}/, done)
    })
  })

  describe('GET /unknown', () => {
    it('unknown endpoint returns 404', (done) => {
      request(app).get('/unknown').expect(404, done)
    }, 10000)
  })

  describe('POST /instance/:instanceId/credentials/sign', () => {
    it('returns 400 if no body', (done) => {
      request(app)
        .post('/instance/testing/credentials/sign')
        .expect('Content-Type', /json/)
        .expect(400, done)
    })

    it('returns 404 if no seed for tenant name', async () => {
      const unSignedVC = getUnsignedVC()
      const response = await request(app)
        .post('/instance/wrongTenantName/credentials/sign')
        .send(unSignedVC)

      expect(response.header['content-type']).to.have.string('json')
      expect(response.status).to.eql(404)
    })

    it('returns the submitted vc version 2, signed with test key', async () => {
      const sentCred = getUnsignedVC2WithStatus()
      const response = await request(app)
        .post('/instance/testing/credentials/sign')
        .send(sentCred)

      expect(response.header['content-type']).to.have.string('json')
      expect(response.status).to.eql(200)

      const returnedCred = JSON.parse(JSON.stringify(response.body))
      const proof = returnedCred.proof
      delete returnedCred.proof
      sentCred.issuer.id = signingDID
      expect(sentCred).to.eql(returnedCred)
      expect(proof.type).to.eql('Ed25519Signature2020')
      expect(proof.verificationMethod).to.eql(verificationMethod)
    })

    it('returns the submitted vc, signed with test key', async () => {
      const sentCred = getUnsignedVCWithStatus()
      const response = await request(app)
        .post('/instance/testing/credentials/sign')
        .send(sentCred)

      expect(response.header['content-type']).to.have.string('json')
      expect(response.status).to.eql(200)

      const returnedCred = JSON.parse(JSON.stringify(response.body))
      const proof = returnedCred.proof
      delete returnedCred.proof
      sentCred.issuer.id = signingDID
      expect(sentCred).to.eql(returnedCred)
      expect(proof.type).to.eql('Ed25519Signature2020')
      expect(proof.verificationMethod).to.eql(verificationMethod)
    })

    it('sets the issuer.id to signing DID', (done) => {
      request(app)
        .post('/instance/testing/credentials/sign')
        .send(getUnsignedVCWithStatus())
        .expect('Content-Type', /json/)
        .expect((res) => expect(res.body.issuer.id).to.eql(signingDID))
        .expect(200, done)
    })

    it('adds the suite context', async () => {
      const response = await request(app)
        .post('/instance/testing/credentials/sign')
        .send(getUnsignedVCWithoutSuiteContext())

      expect(response.header['content-type']).to.have.string('json')
      expect(response.status).to.eql(200)

      expect(response.body['@context']).to.include(ed25519_2020suiteContext)
    })

    it('leaves an existing credential status as-is', async () => {
      const statusBeforeSigning = getCredentialStatus()
      const response = await request(app)
        .post('/instance/testing/credentials/sign')
        .send(getUnsignedVCWithStatus())

      expect(response.header['content-type']).to.have.string('json')
      expect(response.status).to.eql(200)
      expect(response.body.credentialStatus).to.eql(statusBeforeSigning)
    })

    it('leaves an existing bitstring credential status as-is with v2', async () => {
      const statusBeforeSigning = getCredentialStatusBitString()
      const response = await request(app)
        .post('/instance/testing/credentials/sign')
        .send(getUnsignedVC2WithStatus())

      expect(response.header['content-type']).to.have.string('json')
      expect(response.status).to.eql(200)
      expect(response.body.credentialStatus).to.eql(statusBeforeSigning)
    })
  })

  describe('POST /credentials/issue (VCALM)', () => {
    const testToken = 'testsecret123'
    const authedTenant = 'authedtest'
    const issuePath = '/credentials/issue'

    beforeEach(() => {
      resetConfig()
      process.env[`TENANT_SEED_${authedTenant}`] =
        'z1AeiPT496wWmo9BG2QYXeTusgFSZPNG3T9wNeTtjrQ3rCB'
      process.env[`TENANT_AUTH_TOKEN_${authedTenant}`] = testToken
      clearIssuerInstances()
    })

    afterEach(() => {
      delete process.env[`TENANT_SEED_${authedTenant}`]
      delete process.env[`TENANT_AUTH_TOKEN_${authedTenant}`]
    })

    it('returns 401 if no authorization header', async () => {
      const response = await request(app)
        .post(issuePath)
        .send({ credential: getUnsignedVC() })

      expect(response.status).to.eql(401)
    })

    it('returns 401 with invalid Bearer token', async () => {
      const response = await request(app)
        .post(issuePath)
        .set('Authorization', 'Bearer wrongtoken')
        .send({ credential: getUnsignedVC() })

      expect(response.status).to.eql(401)
    })

    it('returns 200 with valid Bearer token', async () => {
      const sentCred = getUnsignedVCWithStatus()
      const response = await request(app)
        .post(issuePath)
        .set('Authorization', `Bearer ${testToken}`)
        .send({ credential: sentCred })

      expect(response.header['content-type']).to.have.string('json')
      expect(response.status).to.eql(200)
      expect(response.body.proof.type).to.eql('Ed25519Signature2020')
    })

    it('returns 404 when Basic username is an unknown tenant', async () => {
      const credentials = Buffer.from(`wrongtenant:${testToken}`).toString(
        'base64'
      )
      const response = await request(app)
        .post(issuePath)
        .set('Authorization', `Basic ${credentials}`)
        .send({ credential: getUnsignedVC() })

      expect(response.status).to.eql(404)
    })

    it('returns 401 with wrong password in Basic Auth', async () => {
      const credentials = Buffer.from(`${authedTenant}:wrongpassword`).toString(
        'base64'
      )
      const response = await request(app)
        .post(issuePath)
        .set('Authorization', `Basic ${credentials}`)
        .send({ credential: getUnsignedVC() })

      expect(response.status).to.eql(401)
    })

    it('returns 200 with valid Basic Auth', async () => {
      const sentCred = getUnsignedVCWithStatus()
      const credentials = Buffer.from(`${authedTenant}:${testToken}`).toString(
        'base64'
      )
      const response = await request(app)
        .post(issuePath)
        .set('Authorization', `Basic ${credentials}`)
        .send({ credential: sentCred })

      expect(response.header['content-type']).to.have.string('json')
      expect(response.status).to.eql(200)
      expect(response.body.proof.type).to.eql('Ed25519Signature2020')
    })

    describe('eddsa-rdfc-2022 (DataIntegrityProof)', () => {
      const diTenant = 'ditest'
      const dataIntegrityContext = 'https://w3id.org/security/data-integrity/v2'

      // A v2 credential the DI suite can sign. The eddsa-rdfc-2022 suite is
      // incompatible with the v1 credential context used by the legacy
      // fixtures, so use a minimal v2 credential here.
      const getUnsignedDIVC = () => ({
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:uuid:2fe53dc9-b2ec-4939-9b2c-0d00f6663b6c',
        type: ['VerifiableCredential'],
        issuer: 'did:example:placeholder',
        validFrom: '2023-08-02T17:43:32.903Z',
        credentialSubject: {
          id: 'did:example:subject',
          name: 'Jane Doe'
        }
      })

      beforeEach(() => {
        process.env[`TENANT_SEED_${diTenant}`] =
          'z1AeiPT496wWmo9BG2QYXeTusgFSZPNG3T9wNeTtjrQ3rCB'
        process.env[`TENANT_CRYPTOSUITE_${diTenant}`] = 'eddsa-rdfc-2022'
        resetConfig()
        clearIssuerInstances()
      })

      afterEach(() => {
        delete process.env[`TENANT_SEED_${diTenant}`]
        delete process.env[`TENANT_CRYPTOSUITE_${diTenant}`]
      })

      it('issues a DataIntegrityProof for an eddsa-rdfc-2022 tenant', async () => {
        const credentials = Buffer.from(`${diTenant}:any`).toString('base64')
        const response = await request(app)
          .post(issuePath)
          .set('Authorization', `Basic ${credentials}`)
          .send({ credential: getUnsignedDIVC() })

        expect(response.status).to.eql(200)
        expect(response.body.proof.type).to.eql('DataIntegrityProof')
        expect(response.body.proof.cryptosuite).to.eql('eddsa-rdfc-2022')
      })

      it('injects the required data-integrity context when missing', async () => {
        const credentials = Buffer.from(`${diTenant}:any`).toString('base64')
        const sentCred = getUnsignedDIVC()
        expect(sentCred['@context']).to.not.include(dataIntegrityContext)

        const response = await request(app)
          .post(issuePath)
          .set('Authorization', `Basic ${credentials}`)
          .send({ credential: sentCred })

        expect(response.status).to.eql(200)
        expect(response.body['@context']).to.include(dataIntegrityContext)
      })

      it('does not duplicate an already-present required context', async () => {
        const credentials = Buffer.from(`${diTenant}:any`).toString('base64')
        const sentCred = getUnsignedDIVC()
        sentCred['@context'].push(dataIntegrityContext)

        const response = await request(app)
          .post(issuePath)
          .set('Authorization', `Basic ${credentials}`)
          .send({ credential: sentCred })

        expect(response.status).to.eql(200)
        const occurrences = response.body['@context'].filter(
          (ctx) => ctx === dataIntegrityContext
        )
        expect(occurrences).to.have.lengthOf(1)
      })
    })

    it('returns 400 if credential property is missing', async () => {
      const credentials = Buffer.from(`${authedTenant}:${testToken}`).toString(
        'base64'
      )
      const response = await request(app)
        .post(issuePath)
        .set('Authorization', `Basic ${credentials}`)
        .send({}) // No credential property

      expect(response.status).to.eql(400)
    })

    it('returns 200 for tenant without authToken using Basic Auth (password ignored)', async () => {
      const noAuthTenant = 'testing' // Default tenant with no auth token
      const sentCred = getUnsignedVCWithStatus()
      const credentials = Buffer.from(`${noAuthTenant}:any`).toString('base64')
      const response = await request(app)
        .post(issuePath)
        .set('Authorization', `Basic ${credentials}`)
        .send({ credential: sentCred })

      expect(response.header['content-type']).to.have.string('json')
      expect(response.status).to.eql(200)
      expect(response.body.proof.type).to.eql('Ed25519Signature2020')
    })

    it('returns 404 for non-existent tenant (Basic Auth)', async () => {
      const credentials = Buffer.from('nonexistenttenant:sometoken').toString(
        'base64'
      )
      const response = await request(app)
        .post(issuePath)
        .set('Authorization', `Basic ${credentials}`)
        .send({ credential: getUnsignedVC() })

      expect(response.status).to.eql(404)
    })

    it('returns 401 with malformed Basic Auth (missing encoded part)', async () => {
      const response = await request(app)
        .post(issuePath)
        .set('Authorization', 'Basic ') // Missing encoded part
        .send({ credential: getUnsignedVC() })

      expect(response.status).to.eql(401)
    })

    it('returns 401 with Basic Auth missing username', async () => {
      const credentials = Buffer.from(`:${testToken}`).toString('base64') // Empty username
      const response = await request(app)
        .post(issuePath)
        .set('Authorization', `Basic ${credentials}`)
        .send({ credential: getUnsignedVC() })

      expect(response.status).to.eql(401)
    })

    it('returns 401 with Basic Auth missing password', async () => {
      const credentials = Buffer.from(`${authedTenant}:`).toString('base64') // Empty password
      const response = await request(app)
        .post(issuePath)
        .set('Authorization', `Basic ${credentials}`)
        .send({ credential: getUnsignedVC() })

      expect(response.status).to.eql(401)
    })

    it('returns 401 with invalid Bearer format (missing token)', async () => {
      const response = await request(app)
        .post(issuePath)
        .set('Authorization', 'Bearer ') // Missing token
        .send({ credential: getUnsignedVC() })

      expect(response.status).to.eql(401)
    })

    it('returns 401 with unknown authorization scheme', async () => {
      const response = await request(app)
        .post(issuePath)
        .set('Authorization', 'Digest username=test') // Unknown scheme
        .send({ credential: getUnsignedVC() })

      expect(response.status).to.eql(401)
    })

    it('returns 401 with malformed Basic Auth (invalid base64)', async () => {
      const response = await request(app)
        .post(issuePath)
        .set('Authorization', 'Basic not-valid-base64!!!') // Invalid base64
        .send({ credential: getUnsignedVC() })

      expect(response.status).to.eql(401)
    })
  })

  describe('DID:web', () => {
    const tenantName = 'apptest'

    before(() => {
      resetConfig()
      process.env[`TENANT_SEED_${tenantName}`] =
        'z1AeiPT496wWmo9BG2QYXeTusgFSZPNG3T9wNeTtjrQ3rCB'
      process.env[`TENANT_DIDMETHOD_${tenantName}`] = 'web'
      process.env[`TENANT_DID_URL_${tenantName}`] = 'https://example.com'
    })

    after(() => {
      delete process.env[`TENANT_SEED_${tenantName}`]
      delete process.env[`TENANT_DIDMETHOD_${tenantName}`]
      delete process.env[`TENANT_DID_URL_${tenantName}`]
    })

    it('signs with a did:web', async () => {
      await request(app)
        .post(`/instance/${tenantName}/credentials/sign`)
        .send(getUnsignedVCWithStatus())
        .expect('Content-Type', /json/)
        .expect((res) =>
          expect(res.body.issuer.id).to.eql('did:web:example.com')
        )
        .expect(200)
    })
  })

  describe('DID:web with eddsa-rdfc-2022', () => {
    const tenantName = 'apptestdiweb'

    // The did:web driver returns an Ed25519VerificationKey2020, whose signer
    // reports no `algorithm`. Without a Multikey conversion DataIntegrityProof
    // rejects it and every did:web + eddsa-rdfc-2022 tenant 500s, while the
    // same tenant on the legacy suite signs fine.
    const getUnsignedDIVC = () => ({
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:0a5c4b3e-6d1f-4b0a-9a2f-7c8d4e1b9f30',
      type: ['VerifiableCredential'],
      issuer: 'did:example:placeholder',
      validFrom: '2023-08-02T17:43:32.903Z',
      credentialSubject: { id: 'did:example:subject', name: 'Jane Doe' }
    })

    before(() => {
      resetConfig()
      clearIssuerInstances()
      process.env[`TENANT_SEED_${tenantName}`] =
        'z1AeiPT496wWmo9BG2QYXeTusgFSZPNG3T9wNeTtjrQ3rCB'
      process.env[`TENANT_DIDMETHOD_${tenantName}`] = 'web'
      process.env[`TENANT_DID_URL_${tenantName}`] = 'https://example.com/ui/x'
      process.env[`TENANT_CRYPTOSUITE_${tenantName}`] = 'eddsa-rdfc-2022'
    })

    after(() => {
      delete process.env[`TENANT_SEED_${tenantName}`]
      delete process.env[`TENANT_DIDMETHOD_${tenantName}`]
      delete process.env[`TENANT_DID_URL_${tenantName}`]
      delete process.env[`TENANT_CRYPTOSUITE_${tenantName}`]
    })

    it('issues a DataIntegrityProof from a path-form did:web tenant', async () => {
      const response = await request(app)
        .post(`/instance/${tenantName}/credentials/sign`)
        .send(getUnsignedDIVC())

      expect(response.status).to.eql(200)
      expect(response.body.issuer.id ?? response.body.issuer).to.eql(
        'did:web:example.com:ui:x'
      )
      expect(response.body.proof.type).to.eql('DataIntegrityProof')
      expect(response.body.proof.cryptosuite).to.eql('eddsa-rdfc-2022')
      expect(response.body.proof.verificationMethod).to.contain(
        'did:web:example.com:ui:x#'
      )
    })
  })

  /**
   * The published DID document.
   *
   * These tests exist because of gap H1: a hand-maintained document said one
   * thing while the configured seed produced another, and nothing compared
   * them. The anti-drift test below is the comparison, made permanent.
   */
  describe('GET /instance/:instanceId/did.json', () => {
    const tenantName = 'apptestdidjson'
    const tenantSeed = 'z1AeiPT496wWmo9BG2QYXeTusgFSZPNG3T9wNeTtjrQ3rCB'
    const tenantUrl = 'https://example.com/ui/ccp-test'
    const tenantDid = 'did:web:example.com:ui:ccp-test'
    const ecdsaWebTenant = 'apptestdidjsonecdsa'
    // The same seed and url on the default (legacy Ed25519Signature2020) suite,
    // to prove the published verification-method type follows the tenant's
    // configuration and nothing else moves with it.
    const legacyTenant = 'apptestdidjsonlegacy'

    const getUnsignedDIVC = () => ({
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:6bd1a0ff-1d7a-4a3c-8f9a-2a6b0b3a1c44',
      type: ['VerifiableCredential'],
      issuer: 'did:example:placeholder',
      validFrom: '2023-08-02T17:43:32.903Z',
      credentialSubject: { id: 'did:example:subject', name: 'Jane Doe' }
    })

    before(async () => {
      resetConfig()
      clearIssuerInstances()
      process.env[`TENANT_SEED_${tenantName}`] = tenantSeed
      process.env[`TENANT_DIDMETHOD_${tenantName}`] = 'web'
      process.env[`TENANT_DID_URL_${tenantName}`] = tenantUrl
      process.env[`TENANT_CRYPTOSUITE_${tenantName}`] = 'eddsa-rdfc-2022'
      // A did:web tenant on the refused suite, to prove the refusal holds at
      // the publication boundary and not only at the signing one. It carries
      // minted key material rather than a seed because an ecdsa-rdfc-2019
      // tenant declaring a seed is now refused at startup — the refusal under
      // test here is the later one, about the DID method.
      const ecdsaKeyMaterial = await generateEcdsaKeyMaterial()
      process.env[`TENANT_KEY_PUBLIC_${ecdsaWebTenant}`] =
        ecdsaKeyMaterial.publicKeyMultibase
      process.env[`TENANT_KEY_SECRET_${ecdsaWebTenant}`] =
        ecdsaKeyMaterial.secretKeyMultibase
      process.env[`TENANT_DIDMETHOD_${ecdsaWebTenant}`] = 'web'
      process.env[`TENANT_DID_URL_${ecdsaWebTenant}`] = tenantUrl
      process.env[`TENANT_CRYPTOSUITE_${ecdsaWebTenant}`] = 'ecdsa-rdfc-2019'
      // Same seed, same url, no TENANT_CRYPTOSUITE_ — the legacy default.
      process.env[`TENANT_SEED_${legacyTenant}`] = tenantSeed
      process.env[`TENANT_DIDMETHOD_${legacyTenant}`] = 'web'
      process.env[`TENANT_DID_URL_${legacyTenant}`] = tenantUrl
    })

    after(() => {
      delete process.env[`TENANT_SEED_${tenantName}`]
      delete process.env[`TENANT_DIDMETHOD_${tenantName}`]
      delete process.env[`TENANT_DID_URL_${tenantName}`]
      delete process.env[`TENANT_CRYPTOSUITE_${tenantName}`]
      delete process.env[`TENANT_KEY_PUBLIC_${ecdsaWebTenant}`]
      delete process.env[`TENANT_KEY_SECRET_${ecdsaWebTenant}`]
      delete process.env[`TENANT_DIDMETHOD_${ecdsaWebTenant}`]
      delete process.env[`TENANT_DID_URL_${ecdsaWebTenant}`]
      delete process.env[`TENANT_CRYPTOSUITE_${ecdsaWebTenant}`]
      delete process.env[`TENANT_SEED_${legacyTenant}`]
      delete process.env[`TENANT_DIDMETHOD_${legacyTenant}`]
      delete process.env[`TENANT_DID_URL_${legacyTenant}`]
    })

    it('serves a document whose id is the DID that tenant signs with', async () => {
      const document = await request(app)
        .get(`/instance/${tenantName}/did.json`)
        .expect('Content-Type', /json/)
        .expect(200)

      expect(document.body.id).to.eql(tenantDid)

      // Not asserted against a literal alone: sign with the same tenant and
      // compare. If the published identifier and the issued one ever part
      // company, this is the test that says so.
      const signed = await request(app)
        .post(`/instance/${tenantName}/credentials/sign`)
        .send(getUnsignedDIVC())
        .expect(200)

      expect(signed.body.issuer.id ?? signed.body.issuer).to.eql(
        document.body.id
      )
      // The fragment is the fact Certree's already-scored sitting rests on: the
      // credential's `proof.verificationMethod` must name the published method.
      expect(signed.body.proof.verificationMethod).to.eql(
        document.body.verificationMethod[0].id
      )
      expect(signed.body.proof.verificationMethod).to.eql(
        document.body.assertionMethod[0]
      )
    })

    it('publishes the key under verificationMethod, referenced by fragment', async () => {
      // The normalised shape. `@interop/did-web-resolver` embeds the whole
      // method inside `assertionMethod` and emits no `verificationMethod`
      // array; DID Core permits that, but a wallet that rejects it is not
      // wrong, and this harness has to keep vendor failures attributable to
      // the vendor. `didWeb.js` re-expresses the driver's own output — it does
      // not compose a document from key material, which would be the copy this
      // endpoint exists to avoid.
      const response = await request(app)
        .get(`/instance/${tenantName}/did.json`)
        .expect(200)

      expect(response.body.verificationMethod)
        .to.be.an('array')
        .with.lengthOf(1)
      const [method] = response.body.verificationMethod
      expect(method.controller).to.eql(tenantDid)
      expect(method.publicKeyMultibase).to.be.a('string')
      expect(method.id).to.eql(`${tenantDid}#${method.publicKeyMultibase}`)

      // References, not embeds.
      expect(response.body.assertionMethod).to.eql([method.id])
      expect(response.body.authentication).to.eql([method.id])
    })

    it("types the verification method for the tenant's cryptosuite", async () => {
      // eddsa-rdfc-2022 signs a DataIntegrityProof, whose verifier resolves the
      // method through Ed25519Multikey and expects `Multikey`. Ours translates
      // a 2020-typed method for us; a third-party wallet need not.
      const diProof = await request(app)
        .get(`/instance/${tenantName}/did.json`)
        .expect(200)

      expect(diProof.body.verificationMethod[0].type).to.eql('Multikey')
      expect(diProof.body['@context']).to.eql([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/multikey/v1'
      ])

      const legacy = await request(app)
        .get(`/instance/${legacyTenant}/did.json`)
        .expect(200)

      expect(legacy.body.verificationMethod[0].type).to.eql(
        'Ed25519VerificationKey2020'
      )
      expect(legacy.body['@context']).to.eql([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1'
      ])

      // Same seed, same url, same key, same fragment: only the type and the
      // context move with the configured suite. If this ever fails, an already
      // issued credential's `proof.verificationMethod` has been invalidated.
      expect(legacy.body.verificationMethod[0].id).to.eql(
        diProof.body.verificationMethod[0].id
      )
      expect(legacy.body.verificationMethod[0].publicKeyMultibase).to.eql(
        diProof.body.verificationMethod[0].publicKeyMultibase
      )
    })

    it('declares no vestigial contexts or unused relationships', async () => {
      // The driver declares the x25519 suite context but emits no
      // `keyAgreement`. An unused context declaration is harmless to
      // verification and reads as a defect to anyone scoring the document, so
      // it is dropped rather than backed with a key we have no use for.
      const response = await request(app)
        .get(`/instance/${tenantName}/did.json`)
        .expect(200)

      expect(response.body['@context'].join(' ')).to.not.contain('x25519')
      expect(response.body.keyAgreement).to.be.undefined
      expect(response.body.capabilityInvocation).to.be.undefined
      expect(response.body.capabilityDelegation).to.be.undefined
    })

    it('serves the verification method getSigningMaterial derives for the same seed and url', async () => {
      // The anti-drift property, asserted rather than assumed. The document is
      // derived from the same seed + url through the same driver as the signing
      // key, so a divergence here means the two paths have been allowed to fork.
      // Normalisation moved where the method appears; it must not have changed
      // any of the driver's own values, so this still compares against the
      // driver's embedded method.
      const response = await request(app)
        .get(`/instance/${tenantName}/did.json`)
        .expect(200)

      const { didDocument } = await getSigningMaterial({
        method: 'web',
        keyMaterial: ed25519SeedMaterial(await decodeSeed(tenantSeed)),
        url: tenantUrl,
        cryptosuite: 'eddsa-rdfc-2022'
      })

      const [derived] = didDocument.assertionMethod
      const [published] = response.body.verificationMethod

      expect(response.body.id).to.eql(didDocument.id)
      expect(published.id).to.eql(derived.id)
      expect(published.controller).to.eql(derived.controller)
      expect(published.publicKeyMultibase).to.eql(derived.publicKeyMultibase)
    })

    it('404s for a did:key tenant, which has no document to host', async () => {
      await request(app)
        .get(`/instance/${TEST_TENANT_NAME}/did.json`)
        .expect('Content-Type', /json/)
        .expect(404)
    })

    it('404s for an unknown tenant', async () => {
      await request(app).get('/instance/nosuchtenant/did.json').expect(404)
    })

    it('refuses to publish for an ecdsa-rdfc-2019 did:web tenant', async () => {
      // Such a tenant cannot sign at all — `getSigningMaterial` refuses it — so
      // publishing an Ed25519 document for it would put a key on the wire that
      // never issues anything. Same refusal, same words.
      const response = await request(app)
        .get(`/instance/${ecdsaWebTenant}/did.json`)
        .expect(400)

      expect(response.body.message).to.match(/did:key only/)
    })
  })

  describe('/did-web-generator', () => {
    it('returns a new did:web', async () => {
      await request(app)
        .post(`/did-web-generator`)
        .send({
          url: 'https://raw.githubusercontent.com/jchartrand/didWebTest/main'
        })
        .expect('Content-Type', /json/)
        .expect((res) => {
          expect(res.body.seed).to.exist
          expect(res.body.didDocument.id).to.eql(
            'did:web:raw.githubusercontent.com:jchartrand:didWebTest:main'
          )
          expect(res.body.did).to.eql(
            'did:web:raw.githubusercontent.com:jchartrand:didWebTest:main'
          )
        })
        .expect(200)
    })

    it('returns the same normalised shape the publication endpoint serves', async () => {
      // Two surfaces answering "what does our did:web document look like" must
      // not disagree, or the copy-by-hand path this service is trying to
      // retire acquires a second source.
      await request(app)
        .post(`/did-web-generator`)
        .send({
          url: 'https://raw.githubusercontent.com/jchartrand/didWebTest/main'
        })
        .expect(200)
        .expect((res) => {
          const { didDocument } = res.body
          expect(didDocument.verificationMethod)
            .to.be.an('array')
            .with.lengthOf(1)
          const [method] = didDocument.verificationMethod
          // No tenant, so no configured suite: the generator previews the
          // default suite's shape.
          expect(method.type).to.eql('Ed25519VerificationKey2020')
          expect(didDocument['@context']).to.eql([
            'https://www.w3.org/ns/did/v1',
            'https://w3id.org/security/suites/ed25519-2020/v1'
          ])
          expect(didDocument.assertionMethod).to.eql([method.id])
          expect(didDocument.authentication).to.eql([method.id])
          expect(didDocument.keyAgreement).to.be.undefined
        })
    })
  })

  describe('/did-key-generator', () => {
    it('returns a new did:key', async () => {
      await request(app)
        .get(`/did-key-generator`)
        .expect('Content-Type', /json/)
        .expect((res) => {
          expect(res.body.seed).to.exist
          expect(res.body.didDocument.id).to.contain('did:key')
          expect(res.body.did).to.contain('did:key')
        })
        .expect(200)
    })
  })

  describe('/healthz', () => {
    it('returns 200 when healthy', async () => {
      await request(app)
        .get(`/healthz`)
        .expect('Content-Type', /json/)
        .expect((res) => {
          expect(res.body.message).to.contain('ok')
        })
        .expect(200)
    })
  })

  describe('/healthz fail', () => {
    // to force an error with the health check, we remove the
    // test issuer instance and it's signing seed

    beforeEach(async () => {
      // make sure all seeds have been loaded before we remove the test seed
      await getTenantSeed(TEST_TENANT_NAME)
      deleteSeed(TEST_TENANT_NAME)
      clearIssuerInstances()
    })

    after(async () => {
      resetConfig()
    })

    it('returns 503 when not healthy', async () => {
      await request(app)
        .get(`/healthz`)
        .expect('Content-Type', /json/)
        .expect((res) => {
          console.log('the body:')
          console.log(res.body)
          expect(res.body.error).to.contain('error')
        })
        .expect(503)
    })
  })
})
