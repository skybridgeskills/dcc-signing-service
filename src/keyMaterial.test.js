import { expect } from 'chai'
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey'
import {
  ECDSA_RDFC_2019,
  KEY_MATERIAL_MULTIKEY,
  generateEcdsaKeyMaterial,
  loadEcdsaKeyPair
} from './keyMaterial.js'
import { getSigningMaterial } from './issue.js'
import { resetConfig, getTenantSeed } from './config.js'

/**
 * The test that binds the minting CLI to the loader.
 *
 * ⚠️ **This is the whole milestone.** `EcdsaMultikey.generate({ seed })`
 * silently discarded the seed, so an `ecdsa-rdfc-2019` tenant minted a fresh
 * issuer DID on every restart, redeploy and replica — and nothing ever said so.
 * The proof was run by hand once; it runs here forever.
 */
const tenant = 'keymaterialtest'

/** Every env var this file writes, so nothing leaks into a later test file. */
const tenantVars = [
  `TENANT_SEED_${tenant}`,
  `TENANT_KEY_PUBLIC_${tenant}`,
  `TENANT_KEY_SECRET_${tenant}`,
  `TENANT_CRYPTOSUITE_${tenant}`,
  `TENANT_DIDMETHOD_${tenant}`
]

const clearTenant = () => {
  for (const name of tenantVars) delete process.env[name]
  resetConfig()
}

/** Declares the tenant, then loads it — the real startup path, not a stub. */
const loadTenant = async (declaration) => {
  clearTenant()
  for (const [suffix, value] of Object.entries(declaration)) {
    process.env[`TENANT_${suffix}_${tenant}`] = value
  }
  return getTenantSeed(tenant)
}

const refusal = async (declaration) => {
  try {
    await loadTenant(declaration)
  } catch (error) {
    return error
  }
  return null
}

describe('ECDSA key material', () => {
  beforeEach(clearTenant)
  afterEach(clearTenant)
  after(clearTenant)

  describe('mint → persist → load round trip', () => {
    it('produces the same did:key across two independent loads', async () => {
      const minted = await generateEcdsaKeyMaterial()
      expect(minted.kind).to.eql(KEY_MATERIAL_MULTIKEY)
      expect(minted.publicKeyMultibase).to.be.a('string')
      expect(minted.secretKeyMultibase).to.be.a('string')

      // Two loads from the persisted halves alone, each starting from a fresh
      // object, as two service starts would. Nothing is shared between them but
      // the two strings a provisioning run would have written down.
      const persisted = {
        kind: minted.kind,
        publicKeyMultibase: minted.publicKeyMultibase,
        secretKeyMultibase: minted.secretKeyMultibase
      }
      const load = () =>
        getSigningMaterial({
          method: 'key',
          keyMaterial: { ...persisted },
          cryptosuite: ECDSA_RDFC_2019
        })

      const first = await load()
      const second = await load()

      // P-256 did:key carries the `zDna` multibase header; Ed25519 carries `z6Mk`.
      expect(first.didDocument.id).to.match(/^did:key:zDna/)
      expect(second.didDocument.id).to.eql(first.didDocument.id)
      // And it is the DID the minting CLI printed, not merely a stable one.
      expect(first.didDocument.id).to.eql(
        `did:key:${minted.publicKeyMultibase}`
      )
    })

    it('loads a signing key, not just an identifier', async () => {
      // A stable DID nobody can sign as would satisfy the assertion above and
      // be useless. `EcdsaMultikey.from` accepts material it cannot sign with,
      // so the signature is the thing that proves the secret half survived.
      const minted = await generateEcdsaKeyMaterial()
      const { key } = await getSigningMaterial({
        method: 'key',
        keyMaterial: minted,
        cryptosuite: ECDSA_RDFC_2019
      })
      const signer = key.signer()
      expect(signer.algorithm).to.eql('P-256')

      const signature = await signer.sign({
        data: new TextEncoder().encode('round trip')
      })
      expect(signature).to.have.length(64)
    })

    it('reloads through EcdsaMultikey.from with the halves alone', async () => {
      // The library-level step the service's load is built on, asserted
      // separately so an upgrade that breaks it fails here rather than
      // somewhere further downstream.
      const minted = await generateEcdsaKeyMaterial()
      const keyPair = await loadEcdsaKeyPair(minted)
      const exported = await keyPair.export({
        publicKey: true,
        secretKey: true
      })

      expect(exported.publicKeyMultibase).to.eql(minted.publicKeyMultibase)
      expect(exported.secretKeyMultibase).to.eql(minted.secretKeyMultibase)
    })

    it('refuses material that is not a P-256 key pair', async () => {
      let error
      try {
        await loadEcdsaKeyPair({
          kind: KEY_MATERIAL_MULTIKEY,
          publicKeyMultibase: 'zDnanotarealkey',
          secretKeyMultibase: 'z42tnotarealkey'
        })
      } catch (e) {
        error = e
      }
      expect(error, 'expected unusable halves to be refused').to.exist
      expect(error.message).to.match(/not a usable P-256 key pair/)
    })
  })

  describe('tenant discovery', () => {
    it('sees a tenant that declares only key material (finding F3)', async () => {
      // ⚠️ Discovery filtered on `TENANT_SEED_` alone, so an ECDSA tenant was
      // INVISIBLE rather than merely unsigned — a 404 at issuance with nothing
      // to explain it. The tenant set is the union of the families now.
      const minted = await generateEcdsaKeyMaterial()
      const config = await loadTenant({
        CRYPTOSUITE: ECDSA_RDFC_2019,
        KEY_PUBLIC: minted.publicKeyMultibase,
        KEY_SECRET: minted.secretKeyMultibase
      })

      expect(config, 'ECDSA tenant should be discoverable').to.exist
      expect(config.keyMaterial.kind).to.eql(KEY_MATERIAL_MULTIKEY)
      expect(config.keyMaterial.publicKeyMultibase).to.eql(
        minted.publicKeyMultibase
      )
      expect(config.didSeed).to.be.undefined
      expect(config.cryptosuite).to.eql(ECDSA_RDFC_2019)
    })

    it('signs for a discovered ECDSA tenant with the configured identity', async () => {
      const minted = await generateEcdsaKeyMaterial()
      const config = await loadTenant({
        CRYPTOSUITE: ECDSA_RDFC_2019,
        KEY_PUBLIC: minted.publicKeyMultibase,
        KEY_SECRET: minted.secretKeyMultibase
      })
      const { didDocument } = await getSigningMaterial({
        method: 'key',
        keyMaterial: config.keyMaterial,
        cryptosuite: config.cryptosuite
      })
      expect(didDocument.id).to.eql(`did:key:${minted.publicKeyMultibase}`)
    })

    it('still reads a seed tenant exactly as before', async () => {
      const config = await loadTenant({
        SEED: 'z1AeiPT496wWmo9BG2QYXeTusgFSZPNG3T9wNeTtjrQ3rCB'
      })
      expect(config.keyMaterial.kind).to.eql('ed25519-seed')
      expect(config.didSeed).to.eql(config.keyMaterial.seed)
      expect(config.didSeed).to.be.an.instanceOf(Uint8Array)
    })
  })

  /**
   * One test per refused declaration.
   *
   * ⚠️ These are the part that makes the fix good rather than merely working.
   * The defect existed because a discarded seed failed *silently*; a fallback
   * anywhere in here would reintroduce exactly that, one variable over.
   */
  describe('startup refusals', () => {
    it('refuses ecdsa-rdfc-2019 declared with only a seed', async () => {
      const error = await refusal({
        CRYPTOSUITE: ECDSA_RDFC_2019,
        SEED: 'z1AeiPT496wWmo9BG2QYXeTusgFSZPNG3T9wNeTtjrQ3rCB'
      })
      expect(error, 'expected an ecdsa seed to be refused').to.exist
      expect(error.message).to.contain(tenant)
      expect(error.message).to.match(/discards its seed argument/)
    })

    it('refuses a tenant declaring both a seed and key material', async () => {
      const minted = await generateEcdsaKeyMaterial()
      const error = await refusal({
        CRYPTOSUITE: ECDSA_RDFC_2019,
        SEED: 'z1AeiPT496wWmo9BG2QYXeTusgFSZPNG3T9wNeTtjrQ3rCB',
        KEY_PUBLIC: minted.publicKeyMultibase,
        KEY_SECRET: minted.secretKeyMultibase
      })
      expect(error, 'expected an ambiguous declaration to be refused').to.exist
      expect(error.message).to.contain(tenant)
      expect(error.message).to.match(/one kind of key material, not both/)
    })

    it('refuses half a key pair, in either direction', async () => {
      const minted = await generateEcdsaKeyMaterial()

      const publicOnly = await refusal({
        CRYPTOSUITE: ECDSA_RDFC_2019,
        KEY_PUBLIC: minted.publicKeyMultibase
      })
      expect(publicOnly, 'expected a public half alone to be refused').to.exist
      expect(publicOnly.message).to.contain(`TENANT_KEY_SECRET_${tenant}`)

      const secretOnly = await refusal({
        CRYPTOSUITE: ECDSA_RDFC_2019,
        KEY_SECRET: minted.secretKeyMultibase
      })
      // ⚠️ Reachable only because `TENANT_KEY_SECRET_` is a discovery family
      // too. Discovering on the public half alone would make this tenant
      // vanish rather than fail.
      expect(secretOnly, 'expected a secret half alone to be refused').to.exist
      expect(secretOnly.message).to.contain(`TENANT_KEY_PUBLIC_${tenant}`)
    })

    it('refuses key material on a tenant that is not ecdsa-rdfc-2019', async () => {
      const minted = await generateEcdsaKeyMaterial()

      for (const cryptosuite of ['eddsa-rdfc-2022', undefined]) {
        const declaration = {
          KEY_PUBLIC: minted.publicKeyMultibase,
          KEY_SECRET: minted.secretKeyMultibase
        }
        if (cryptosuite) declaration.CRYPTOSUITE = cryptosuite

        const error = await refusal(declaration)
        expect(
          error,
          `expected key material with cryptosuite ${cryptosuite} to be refused`
        ).to.exist
        expect(error.message).to.contain(tenant)
        expect(error.message).to.match(/consumed only by ecdsa-rdfc-2019/)
      }
    })

    it('refuses to sign ecdsa-rdfc-2019 from seed material', async () => {
      // Discovery cannot produce this pairing, but `getSigningMaterial` is
      // exported and called directly. Refusing here too means the fallback to
      // a randomly generated key has no route back into the service at all.
      let error
      try {
        await getSigningMaterial({
          method: 'key',
          keyMaterial: { kind: 'ed25519-seed', seed: new Uint8Array(32) },
          cryptosuite: ECDSA_RDFC_2019
        })
      } catch (e) {
        error = e
      }
      expect(error, 'expected seed material to be refused for ecdsa').to.exist
      expect(error.message).to.match(/requires 'multikey' key material/)
    })
  })

  describe('did:web is still refused for ecdsa-rdfc-2019', () => {
    it('refuses to sign, unchanged', async () => {
      const minted = await generateEcdsaKeyMaterial()
      let error
      try {
        await getSigningMaterial({
          method: 'web',
          keyMaterial: minted,
          url: 'https://example.com/issuers/ecdsa',
          cryptosuite: ECDSA_RDFC_2019
        })
      } catch (e) {
        error = e
      }
      expect(error, 'expected did:web + ecdsa-rdfc-2019 to be refused').to.exist
      expect(error.message).to.match(/did:key only/)
    })
  })

  describe('the defect this replaces', () => {
    it('confirms EcdsaMultikey.generate still discards its seed', async () => {
      // The premise, asserted rather than trusted. If a library upgrade ever
      // makes `generate({ seed })` deterministic, this fails and someone gets
      // to reconsider persisting both halves — which is the flip condition the
      // ADR records, arriving from the library side.
      const seed = new Uint8Array(32).fill(7)
      const [a, b] = await Promise.all([
        EcdsaMultikey.generate({ curve: 'P-256', seed }),
        EcdsaMultikey.generate({ curve: 'P-256', seed })
      ])
      expect(a.publicKeyMultibase).to.not.eql(b.publicKeyMultibase)
    })
  })
})
