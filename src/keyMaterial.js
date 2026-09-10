import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey'

/**
 * Tenant key material: the two shapes a tenant's signing key can be configured
 * in, and the rules for reading a tenant's declaration of one.
 *
 * ⚠️ **This is a local mirror of `@skybridgeskills/vc-signer`'s `KeyMaterial`
 * union (`vcalm-status-service/packages/vc-signer/src/types.ts`), in plain
 * JavaScript, and it is deliberately TRANSITIONAL.** Recorded owner intent is
 * that this service is converted to TypeScript and adopts `vc-signer`; when it
 * does, this module is *deleted*, not redesigned. That is why the discriminant
 * and the field names are copied verbatim rather than improved on, and it is
 * why this is not a fourth independent cryptosuite policy in this repo.
 *
 * Why two variants at all — `vc-signer`'s own comment, which is the reason this
 * module exists:
 *
 * > ECDSA has no deterministic seed derivation in the stack we build on, so
 * > P-256 material is generated once and persisted at provisioning time — and
 * > both halves are persisted, because the WebCrypto import path cannot recover
 * > a P-256 public key from the secret multikey alone.
 *
 * Concretely: `@digitalbazaar/ecdsa-multikey@1.8.0`'s `generate()` destructures
 * only `{id, controller, curve, keyAgreement}` (`lib/index.js:23-25`), so a
 * `seed` handed to it is **silently discarded** and `webcrypto.subtle.generateKey`
 * runs non-deterministically. Its only raw-import path, `fromRaw`
 * (`lib/index.js:122-138`), requires the public key as a **mandatory
 * `Uint8Array`** and cannot recompute the P-256 point from a secret. So an
 * `ecdsa-rdfc-2019` tenant configured with a seed has no stable issuer DID at
 * all — its DID changed on every restart, redeploy and replica, and the seed
 * was decorative. See
 * `docs/adr/2026-09-10-ecdsa-key-material-both-multibase-halves.md`.
 */

/** Seed-derived Ed25519 material: every tenant that predates ECDSA. */
export const KEY_MATERIAL_ED25519_SEED = 'ed25519-seed'

/** Both persisted multibase halves of a P-256 key pair: ECDSA tenants. */
export const KEY_MATERIAL_MULTIKEY = 'multikey'

/** The one cryptosuite in this service backed by `multikey` material. */
export const ECDSA_RDFC_2019 = 'ecdsa-rdfc-2019'

/** P-256 curve name used for every ecdsa-rdfc-2019 key this service mints. */
const ECDSA_CURVE = 'P-256'

/** The env family a tenant declares each kind of material in. */
export const TENANT_SEED_PREFIX = 'TENANT_SEED_'
export const TENANT_KEY_PUBLIC_PREFIX = 'TENANT_KEY_PUBLIC_'
export const TENANT_KEY_SECRET_PREFIX = 'TENANT_KEY_SECRET_'

/**
 * A declaration counts only if it carries a value. An env var set to the empty
 * string is a provisioning mistake, and reading it as "present" turns a clear
 * refusal below into an obscure failure inside a crypto library later.
 */
const declared = (value) => typeof value === 'string' && value.trim() !== ''

/** The key material an Ed25519 tenant's seed produces. */
export const ed25519SeedMaterial = (seed) => ({
  kind: KEY_MATERIAL_ED25519_SEED,
  seed
})

/** The key material an ECDSA tenant's two persisted halves produce. */
export const multikeyMaterial = ({
  publicKeyMultibase,
  secretKeyMultibase
}) => ({
  kind: KEY_MATERIAL_MULTIKEY,
  publicKeyMultibase,
  secretKeyMultibase
})

/**
 * Decides which kind of key material a tenant has declared, and **refuses
 * loudly** — naming the tenant — for every declaration that is ambiguous or
 * incomplete.
 *
 * ⚠️ **The refusals are the point of this function, not a side effect of it.**
 * The defect this whole module answers existed because a discarded seed failed
 * *silently*: an `ecdsa-rdfc-2019` tenant looked configured, signed correctly,
 * and minted a fresh issuer identity on every boot. The register's C14 records
 * the identical disease one branch over, where an unset
 * `TENANT_CRYPTOSUITE_<T>` silently downgrades a tenant to a non-Data-Integrity
 * proof. So there is deliberately no fallback here for anything — a tenant is
 * either unambiguously declared or the service does not start.
 *
 * Called from tenant discovery, so these throw at startup rather than at the
 * first issuance. Terraform validates the same seed/key XOR at plan time; that
 * is belt-and-braces and not a reason to soften anything here.
 *
 * @param {object} declaration
 * @param {string} declaration.tenant - Tenant name as it appears in the env var
 *   suffix, so the message names the variables the operator actually wrote.
 * @param {string} [declaration.cryptosuite] - `TENANT_CRYPTOSUITE_<T>`.
 * @param {string} [declaration.seed] - `TENANT_SEED_<T>`.
 * @param {string} [declaration.publicKeyMultibase] - `TENANT_KEY_PUBLIC_<T>`.
 * @param {string} [declaration.secretKeyMultibase] - `TENANT_KEY_SECRET_<T>`.
 * @returns {string} `KEY_MATERIAL_ED25519_SEED` or `KEY_MATERIAL_MULTIKEY`.
 * @throws {Error} for any of the four refused declarations.
 */
export function classifyTenantKeyMaterial({
  tenant,
  cryptosuite,
  seed,
  publicKeyMultibase,
  secretKeyMultibase
}) {
  const hasSeed = declared(seed)
  const hasPublic = declared(publicKeyMultibase)
  const hasSecret = declared(secretKeyMultibase)
  const hasKeyMaterial = hasPublic || hasSecret

  const seedVar = `${TENANT_SEED_PREFIX}${tenant}`
  const publicVar = `${TENANT_KEY_PUBLIC_PREFIX}${tenant}`
  const secretVar = `${TENANT_KEY_SECRET_PREFIX}${tenant}`
  const suiteVar = `TENANT_CRYPTOSUITE_${tenant}`

  // Half a key pair cannot sign, and — this being the whole reason both halves
  // are persisted — the missing half cannot be recovered from the one present.
  if (hasPublic !== hasSecret) {
    const [present, missing] = hasPublic
      ? [publicVar, secretVar]
      : [secretVar, publicVar]
    throw new Error(
      `Tenant '${tenant}' declares ${present} but not ${missing}. ECDSA key ` +
        `material is persisted as both multibase halves; the missing half ` +
        `cannot be derived from the other. Mint a fresh pair with ` +
        `'npm run mint:ecdsa' and set both.`
    )
  }

  // Nothing can decide which of the two is authoritative, and guessing would
  // reinstate exactly the silent failure this module exists to end.
  if (hasSeed && hasKeyMaterial) {
    throw new Error(
      `Tenant '${tenant}' declares both ${seedVar} and ${publicVar}/${secretVar}. ` +
        `A tenant carries one kind of key material, not both: a seed for ` +
        `Ed25519 suites, or the two multibase halves for ${ECDSA_RDFC_2019}. ` +
        `Remove whichever is not authoritative.`
    )
  }

  if (hasKeyMaterial && cryptosuite !== ECDSA_RDFC_2019) {
    throw new Error(
      `Tenant '${tenant}' declares ${publicVar}/${secretVar}, but ` +
        `${suiteVar} is ${cryptosuite ? `'${cryptosuite}'` : 'unset'}. ` +
        `Multibase key halves are consumed only by ${ECDSA_RDFC_2019}; every ` +
        `other suite signs from ${seedVar}. Set ${suiteVar}=${ECDSA_RDFC_2019} ` +
        `or configure a seed.`
    )
  }

  if (cryptosuite === ECDSA_RDFC_2019 && hasSeed) {
    throw new Error(
      `Tenant '${tenant}' is configured for ${ECDSA_RDFC_2019} but declares ` +
        `${seedVar}. The P-256 key generator discards its seed argument, so a ` +
        `seed here does not pin anything — the tenant's issuer DID would ` +
        `change on every restart. Mint key material with 'npm run mint:ecdsa' ` +
        `and set ${publicVar} and ${secretVar} instead of ${seedVar}.`
    )
  }

  // Reachable only from a declaration that named the tenant with an empty
  // value, which is a provisioning mistake rather than an absent tenant.
  if (!hasSeed && !hasKeyMaterial) {
    throw new Error(
      `Tenant '${tenant}' declares no usable key material: ${seedVar} is ` +
        `empty or unset, and so are ${publicVar}/${secretVar}.`
    )
  }

  return hasKeyMaterial ? KEY_MATERIAL_MULTIKEY : KEY_MATERIAL_ED25519_SEED
}

/**
 * Refuses key material a cryptosuite cannot use, before any crypto is touched.
 *
 * Tenant discovery already refuses the mismatch, so reaching this means a
 * caller assembled key material by hand — `getSigningMaterial` is exported and
 * used directly by tests and by `signRequestObject`. Mirrors `vc-signer`'s
 * `assertKeyMaterialMatchesCryptosuite`.
 *
 * @param {object} keyMaterial - A member of the key material union.
 * @param {string} [cryptosuite] - The tenant's configured cryptosuite.
 */
export function assertKeyMaterialMatchesCryptosuite(keyMaterial, cryptosuite) {
  const expected =
    cryptosuite === ECDSA_RDFC_2019
      ? KEY_MATERIAL_MULTIKEY
      : KEY_MATERIAL_ED25519_SEED
  if (keyMaterial?.kind !== expected) {
    throw new Error(
      `Cryptosuite '${cryptosuite ?? 'Ed25519Signature2020'}' requires ` +
        `'${expected}' key material, got '${keyMaterial?.kind}'.`
    )
  }
}

/**
 * Turns an ECDSA tenant's two persisted halves back into a live P-256 key pair.
 *
 * This is the load half of the round trip `keyMaterial.test.js` asserts: the
 * same halves always produce the same `did:key`, which is the property the
 * `generate({ seed })` call this replaces could not provide.
 *
 * @param {object} keyMaterial - `multikey` material.
 * @returns {Promise<object>} A key pair usable as a `verificationKeyPair`.
 */
export async function loadEcdsaKeyPair(keyMaterial) {
  assertKeyMaterialMatchesCryptosuite(keyMaterial, ECDSA_RDFC_2019)
  try {
    return await EcdsaMultikey.from({
      type: 'Multikey',
      publicKeyMultibase: keyMaterial.publicKeyMultibase,
      secretKeyMultibase: keyMaterial.secretKeyMultibase
    })
  } catch (cause) {
    throw new Error(
      `Multibase key halves are not a usable P-256 key pair: ${cause.message}`,
      { cause }
    )
  }
}

/**
 * Mints fresh ECDSA key material.
 *
 * Deliberately not exposed over HTTP and deliberately not a magic `'generate'`
 * seed value: this is run out of band, at provisioning time, by
 * `scripts/mint-ecdsa-key-material.js`. Minting at boot is the defect, not the
 * fix — a key that is minted when the process starts is a key that changes when
 * the process restarts.
 *
 * @returns {Promise<object>} `multikey` material carrying both halves.
 */
export async function generateEcdsaKeyMaterial() {
  const keyPair = await EcdsaMultikey.generate({ curve: ECDSA_CURVE })
  const { publicKeyMultibase, secretKeyMultibase } = await keyPair.export({
    publicKey: true,
    secretKey: true
  })
  if (!publicKeyMultibase || !secretKeyMultibase) {
    // Both halves or nothing: a persisted public key with no secret is an
    // identity nobody can sign as, and the reverse cannot be reloaded at all.
    throw new Error(
      'The generated P-256 key pair did not export both multibase halves.'
    )
  }
  return multikeyMaterial({ publicKeyMultibase, secretKeyMultibase })
}
