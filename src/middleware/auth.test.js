import { expect } from 'chai'
import { authenticateAndIdentifyTenant } from './auth.js'
import { resetConfig } from '../config.js'

const tenantName = 'authmwtest'
const seed = 'z1AeiPT496wWmo9BG2QYXeTusgFSZPNG3T9wNeTtjrQ3rCB'

function basicHeader(username, password) {
  const encoded = Buffer.from(`${username}:${password}`, 'utf8').toString(
    'base64'
  )
  return `Basic ${encoded}`
}

function runMiddleware(authHeader) {
  return new Promise((resolve, reject) => {
    const req = { headers: { authorization: authHeader } }
    const res = {}
    const next = (err) => resolve({ err, req })
    Promise.resolve(authenticateAndIdentifyTenant(req, res, next)).catch(reject)
  })
}

describe('auth middleware', () => {
  beforeEach(async () => {
    resetConfig()
    delete process.env[`TENANT_SEED_${tenantName}`]
    delete process.env[`TENANT_AUTH_TOKEN_${tenantName}`]
    delete process.env[`TENANT_SEED_dupA`]
    delete process.env[`TENANT_SEED_dupB`]
    delete process.env[`TENANT_AUTH_TOKEN_dupA`]
    delete process.env[`TENANT_AUTH_TOKEN_dupB`]
    // Other test files (e.g. config.test.js) can leave an invalid seed env var
    // set, which would break tenant-seed loading here. Clear it defensively.
    delete process.env[`TENANT_SEED_configtest`]
  })

  afterEach(async () => {
    resetConfig()
    delete process.env[`TENANT_SEED_${tenantName}`]
    delete process.env[`TENANT_AUTH_TOKEN_${tenantName}`]
    delete process.env[`TENANT_SEED_dupA`]
    delete process.env[`TENANT_SEED_dupB`]
    delete process.env[`TENANT_AUTH_TOKEN_dupA`]
    delete process.env[`TENANT_AUTH_TOKEN_dupB`]
    // Other test files (e.g. config.test.js) can leave an invalid seed env var
    // set, which would break tenant-seed loading here. Clear it defensively.
    delete process.env[`TENANT_SEED_configtest`]
  })

  describe('Basic Auth', () => {
    it('authenticates a password containing a colon (finding 05 regression)', async () => {
      process.env[`TENANT_SEED_${tenantName}`] = seed
      process.env[`TENANT_AUTH_TOKEN_${tenantName}`] = 'p@ss:with:colons'

      const { err, req } = await runMiddleware(
        basicHeader(tenantName, 'p@ss:with:colons')
      )

      expect(err).to.be.undefined
      expect(req.identifiedTenantId).to.eql(tenantName)
    })

    it('rejects a wrong password for a token-configured tenant', async () => {
      process.env[`TENANT_SEED_${tenantName}`] = seed
      process.env[`TENANT_AUTH_TOKEN_${tenantName}`] = 'correct-token'

      const { err } = await runMiddleware(
        basicHeader(tenantName, 'wrong-token')
      )

      expect(err).to.exist
      expect(err.code).to.eql(401)
    })

    it('accepts any password for a tokenless tenant (open mode)', async () => {
      process.env[`TENANT_SEED_${tenantName}`] = seed

      const { err, req } = await runMiddleware(
        basicHeader(tenantName, 'anything-goes')
      )

      expect(err).to.be.undefined
      expect(req.identifiedTenantId).to.eql(tenantName)
    })

    it('rejects Basic Auth with no colon in the credentials', async () => {
      process.env[`TENANT_SEED_${tenantName}`] = seed
      const encoded = Buffer.from(tenantName, 'utf8').toString('base64')

      const { err } = await runMiddleware(`Basic ${encoded}`)

      expect(err).to.exist
      expect(err.code).to.eql(401)
    })
  })

  describe('Bearer Auth', () => {
    it('authenticates a correct token (constant-time compare sanity)', async () => {
      process.env[`TENANT_SEED_${tenantName}`] = seed
      process.env[`TENANT_AUTH_TOKEN_${tenantName}`] = 'bearer-secret'

      const { err, req } = await runMiddleware('Bearer bearer-secret')

      expect(err).to.be.undefined
      expect(req.identifiedTenantId).to.eql(tenantName)
    })

    it('rejects an unknown token', async () => {
      process.env[`TENANT_SEED_${tenantName}`] = seed
      process.env[`TENANT_AUTH_TOKEN_${tenantName}`] = 'bearer-secret'

      const { err } = await runMiddleware('Bearer not-the-token')

      expect(err).to.exist
      expect(err.code).to.eql(401)
    })
  })

  describe('Warnings', () => {
    it('warns once about tokenless tenants on config load', async () => {
      const original = console.warn
      const messages = []
      console.warn = (msg) => messages.push(String(msg))
      try {
        process.env[`TENANT_SEED_${tenantName}`] = seed
        // Trigger a config load via the middleware.
        await runMiddleware(basicHeader(tenantName, 'anything'))
      } finally {
        console.warn = original
      }

      const tokenlessWarnings = messages.filter((m) =>
        m.includes('accept any password on')
      )
      expect(tokenlessWarnings.length).to.eql(1)
      expect(tokenlessWarnings[0]).to.include(tenantName)
    })

    it('warns about duplicate Bearer tokens across tenants', async () => {
      const original = console.warn
      const messages = []
      console.warn = (msg) => messages.push(String(msg))
      try {
        process.env[`TENANT_SEED_dupA`] = seed
        process.env[`TENANT_SEED_dupB`] = seed
        process.env[`TENANT_AUTH_TOKEN_dupA`] = 'shared-token'
        process.env[`TENANT_AUTH_TOKEN_dupB`] = 'shared-token'
        await runMiddleware('Bearer shared-token')
      } finally {
        console.warn = original
      }

      const dupWarnings = messages.filter((m) =>
        m.includes('Duplicate TENANT_AUTH_TOKEN')
      )
      expect(dupWarnings.length).to.be.greaterThan(0)
    })
  })
})
