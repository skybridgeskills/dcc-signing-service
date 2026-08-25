import { expect } from 'chai'
import request from 'supertest'
import { build } from './app.js'
import { resetConfig } from './config.js'
import { clearIssuerInstances } from './issue.js'
import { ECDSA_DID_WEB_REFUSAL } from './didWeb.js'
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020'

/**
 * The OID4VP request-object signing endpoint.
 *
 * ⚠️ **The `kid` test is the reason this endpoint is in this repo**, so it is
 * asserted against the tenant's ACTUAL published `did.json` response rather
 * than against a constant. A constant would pass while the two drifted apart,
 * which is the exact failure — a document saying one thing while the signing
 * key says another — that `didWeb.js` exists to make impossible.
 *
 * ⚠️ And the signature segment is asserted NON-EMPTY, explicitly. The verifier
 * also serves an unsigned request object with an empty third segment as a
 * registered accommodation; that arm is non-conformant and says so. These two
 * must be impossible to confuse, and a test that only counted three segments
 * would pass for both.
 */
describe('POST /instance/:instanceId/openid4vp/request-object/sign', () => {
  let app

  const tenantName = 'reqobjweb'
  const legacyTenant = 'reqobjweblegacy'
  const ecdsaWebTenant = 'reqobjwebecdsa'
  const keyTenant = 'reqobjkey'
  const tenantSeed = 'z1AeiPT496wWmo9BG2QYXeTusgFSZPNG3T9wNeTtjrQ3rCB'
  const tenantUrl = 'https://example.com/ui/ccp-test'

  const requestObject = () => ({
    response_type: 'vp_token',
    response_mode: 'direct_post',
    client_id: 'decentralized_identifier:did:web:example.com:ui:ccp-test',
    nonce: 'a-nonce',
    state: 'a-state'
  })

  const segmentsOf = (jws) => jws.split('.')
  const decode = (segment) =>
    JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'))

  before(async () => {
    resetConfig()
    clearIssuerInstances()
    process.env[`TENANT_SEED_${tenantName}`] = tenantSeed
    process.env[`TENANT_DIDMETHOD_${tenantName}`] = 'web'
    process.env[`TENANT_DID_URL_${tenantName}`] = tenantUrl
    process.env[`TENANT_CRYPTOSUITE_${tenantName}`] = 'eddsa-rdfc-2022'
    // Same seed and url on the legacy default suite, to prove the endpoint
    // follows the tenant's configuration rather than one suite's key type.
    process.env[`TENANT_SEED_${legacyTenant}`] = tenantSeed
    process.env[`TENANT_DIDMETHOD_${legacyTenant}`] = 'web'
    process.env[`TENANT_DID_URL_${legacyTenant}`] = tenantUrl
    // A did:web tenant on the refused suite.
    process.env[`TENANT_SEED_${ecdsaWebTenant}`] = tenantSeed
    process.env[`TENANT_DIDMETHOD_${ecdsaWebTenant}`] = 'web'
    process.env[`TENANT_DID_URL_${ecdsaWebTenant}`] = tenantUrl
    process.env[`TENANT_CRYPTOSUITE_${ecdsaWebTenant}`] = 'ecdsa-rdfc-2019'
    // A did:key tenant, which publishes no document at a URL.
    process.env[`TENANT_SEED_${keyTenant}`] = tenantSeed
    app = await build()
  })

  after(() => {
    for (const t of [tenantName, legacyTenant, ecdsaWebTenant, keyTenant]) {
      delete process.env[`TENANT_SEED_${t}`]
      delete process.env[`TENANT_DIDMETHOD_${t}`]
      delete process.env[`TENANT_DID_URL_${t}`]
      delete process.env[`TENANT_CRYPTOSUITE_${t}`]
    }
  })

  const sign = (tenant = tenantName, body = requestObject()) =>
    request(app)
      .post(`/instance/${tenant}/openid4vp/request-object/sign`)
      .send(body)

  describe('the JWS it returns', () => {
    it('is served as application/oauth-authz-req+jwt', async () => {
      await sign()
        .expect('Content-Type', /application\/oauth-authz-req\+jwt/)
        .expect(200)
    })

    it('⚠️ is three segments with a NON-EMPTY signature — not the alg:none arm', async () => {
      const { text } = await sign().expect(200)
      const segments = segmentsOf(text)

      expect(segments).to.have.lengthOf(3)
      expect(segments[2]).to.not.eql('')
      expect(segments[2].length).to.be.greaterThan(20)
    })

    it('declares alg EdDSA, the request-object typ, and a kid', async () => {
      const { text } = await sign().expect(200)
      const header = decode(segmentsOf(text)[0])

      expect(header.alg).to.eql('EdDSA')
      expect(header.typ).to.eql('oauth-authz-req+jwt')
      expect(header.kid).to.be.a('string')
    })

    it('carries the claims it was given, unaltered', async () => {
      // Choosing the payload is the verifier's job; this endpoint signs what it
      // is handed.
      const { text } = await sign().expect(200)

      expect(decode(segmentsOf(text)[1])).to.eql(requestObject())
    })
  })

  describe('⚠️ the anti-drift property — kid vs the published document', () => {
    it('the kid is an id in the tenant’s ACTUAL published document', async () => {
      // Asserted against the live `did.json` response, never a constant: a
      // constant would keep passing while the two drifted apart, which is the
      // whole failure this endpoint's location exists to prevent.
      const { text } = await sign().expect(200)
      const kid = decode(segmentsOf(text)[0]).kid

      const document = await request(app)
        .get(`/instance/${tenantName}/did.json`)
        .expect(200)

      expect(document.body.verificationMethod.map((m) => m.id)).to.include(kid)
      expect(document.body.authentication).to.include(kid)
    })

    it('the signature VERIFIES against the publicKeyMultibase in that document', async () => {
      // The end of the chain: published key, signed bytes, and a verification
      // that ties them together. If the kid matched but the key did not, this
      // is what would catch it.
      const { text } = await sign().expect(200)
      const [header, payload, signature] = segmentsOf(text)

      const document = await request(app)
        .get(`/instance/${tenantName}/did.json`)
        .expect(200)
      const method = document.body.verificationMethod[0]

      const keyPair = await Ed25519VerificationKey2020.from({
        type: 'Ed25519VerificationKey2020',
        id: method.id,
        controller: method.controller,
        publicKeyMultibase: method.publicKeyMultibase
      })
      const verified = await keyPair.verifier().verify({
        data: new TextEncoder().encode(`${header}.${payload}`),
        signature: Buffer.from(signature, 'base64url')
      })

      expect(verified).to.eql(true)
    })

    it('a tampered payload does NOT verify', async () => {
      // Guards the guard: a verifier that returned true for everything would
      // make the test above vacuous.
      const { text } = await sign().expect(200)
      const [header, , signature] = segmentsOf(text)
      const tampered = Buffer.from(
        JSON.stringify({ ...requestObject(), nonce: 'a-different-nonce' })
      ).toString('base64url')

      const document = await request(app)
        .get(`/instance/${tenantName}/did.json`)
        .expect(200)
      const method = document.body.verificationMethod[0]
      const keyPair = await Ed25519VerificationKey2020.from({
        type: 'Ed25519VerificationKey2020',
        id: method.id,
        controller: method.controller,
        publicKeyMultibase: method.publicKeyMultibase
      })

      const verified = await keyPair.verifier().verify({
        data: new TextEncoder().encode(`${header}.${tampered}`),
        signature: Buffer.from(signature, 'base64url')
      })

      expect(verified).to.eql(false)
    })

    it('a legacy-suite tenant on the same seed signs under the same kid', async () => {
      // The suite names the published verification-method TYPE; it does not
      // move the key. Same seed, same url, same `#fragment`.
      const { text } = await sign(legacyTenant).expect(200)
      const document = await request(app)
        .get(`/instance/${legacyTenant}/did.json`)
        .expect(200)

      expect(decode(segmentsOf(text)[0]).kid).to.eql(
        document.body.verificationMethod[0].id
      )
    })
  })

  describe('⚠️ loud, never lenient — and never an unsigned fallback', () => {
    it('refuses ecdsa-rdfc-2019 + did:web with the SHARED constant', async () => {
      // The third call site for that message, not a fourth wording of it — so
      // signing, publishing and this endpoint cannot drift into disagreeing
      // about whether the combination exists.
      const res = await sign(ecdsaWebTenant).expect(400)
      expect(JSON.stringify(res.body)).to.include(ECDSA_DID_WEB_REFUSAL)
    })

    it('refuses an unknown tenant by name, not with a stack', async () => {
      const res = await sign('a-tenant-that-does-not-exist').expect(404)
      expect(JSON.stringify(res.body)).to.include("Tenant doesn't exist")
    })

    it('refuses a did:key tenant, naming the missing configuration', async () => {
      const res = await sign(keyTenant).expect(404)
      expect(JSON.stringify(res.body)).to.include('TENANT_DIDMETHOD')
    })

    it('refuses an empty body rather than signing nothing', async () => {
      const res = await request(app)
        .post(`/instance/${tenantName}/openid4vp/request-object/sign`)
        .send({})
        .expect(400)
      expect(JSON.stringify(res.body)).to.include('request object')
    })
  })
})
