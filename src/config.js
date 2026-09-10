import { generateSecretKeySeed } from 'bnid'
import {
  SecretsManagerClient,
  GetSecretValueCommand,
  ListSecretsCommand
} from '@aws-sdk/client-secrets-manager'
import decodeSeed from './utils/decodeSeed.js'
import {
  KEY_MATERIAL_MULTIKEY,
  TENANT_SEED_PREFIX,
  TENANT_KEY_PUBLIC_PREFIX,
  TENANT_KEY_SECRET_PREFIX,
  classifyTenantKeyMaterial,
  ed25519SeedMaterial,
  multikeyMaterial
} from './keyMaterial.js'

let CONFIG
const defaultPort = 4006
const defaultConsoleLogLevel = 'silly'
const defaultLogLevel = 'silly'
const testSeed = 'z1AeiPT496wWmo9BG2QYXeTusgFSZPNG3T9wNeTtjrQ3rCB'
export const TEST_TENANT_NAME = 'testing'
export const SECOND_TEST_TENANT_NAME = 'test'
const randomTenantName = 'random'
let DID_SEEDS = {}

/** Maps TENANT_AUTH_TOKEN value -> tenant name (for Bearer auth on /credentials/issue). */
const TOKEN_TO_TENANT = new Map()

function rebuildTokenToTenantMap() {
  TOKEN_TO_TENANT.clear()
  for (const [name, cfg] of Object.entries(DID_SEEDS)) {
    if (cfg && typeof cfg === 'object' && cfg.authToken) {
      const existing = TOKEN_TO_TENANT.get(cfg.authToken)
      if (existing && existing !== name) {
        console.warn(
          `[auth] Duplicate TENANT_AUTH_TOKEN shared by tenants '${existing}' ` +
            `and '${name}'. Bearer auth for this token will resolve to one tenant ` +
            `only. Use a distinct token per tenant.`
        )
      }
      TOKEN_TO_TENANT.set(cfg.authToken, name)
    }
  }
  warnTokenlessTenants()
}

/**
 * Emits one consolidated warning listing tenants without an authToken, which
 * accept Basic Auth with any password on /credentials/issue. Intentional open
 * mode; set a token to require authentication for those tenants.
 */
function warnTokenlessTenants() {
  const tokenless = Object.entries(DID_SEEDS)
    .filter(([, cfg]) => cfg && typeof cfg === 'object' && !cfg.authToken)
    .map(([name]) => name)
  if (tokenless.length) {
    console.warn(
      `[auth] Tenants without TENANT_AUTH_TOKEN accept any password on ` +
        `/credentials/issue: ${tokenless.join(', ')}. Set a token to require ` +
        `authentication for these tenants.`
    )
  }
}

/**
 * Returns the tenant name for a configured auth token, or null.
 *
 * @param {string} token - Bearer token value
 * @returns {string|null}
 */
export function getTenantByToken(token) {
  return TOKEN_TO_TENANT.get(token) ?? null
}

async function getTenantsFromAwsSecretsManager() {
  if (!process.env.TENANTS_AWS_SECRETS) {
    return null
  }
  console.log('Attempting to get tenants from AWS Secrets Manager')

  try {
    const client = new SecretsManagerClient({
      region: process.env.AWS_REGION || 'us-west-2'
    })

    // List all secrets with the specified prefix
    let NextToken = 'INITIAL'
    let SecretList = []

    while (NextToken) {
      NextToken = NextToken === 'INITIAL' ? undefined : NextToken
      const listCommand = new ListSecretsCommand({
        Filters: [
          {
            Key: 'name',
            Values: ['tenant']
          }
        ],
        MaxResults: 100,
        NextToken
      })
      const result = await client.send(listCommand)
      NextToken = result.NextToken
      SecretList = [...SecretList, ...(result.SecretList || [])]
    }

    const validTenants = []

    // Process each tenant secret
    for (const secret of SecretList) {
      const secretName = secret.Name

      // Extract tenant name from the secret name (e.g., "tenant/mcdonalds.com/credentials" -> "mcdonalds.com")
      const tenantNameMatch = secretName.match(/^tenant\/([^/]+)\/credentials$/)
      if (!tenantNameMatch) {
        console.warn(`Skipping secret with invalid format: ${secretName}`)
        continue
      }

      const tenantName = tenantNameMatch[1]

      // Get the secret value
      const getCommand = new GetSecretValueCommand({
        SecretId: secretName
      })

      const secretResponse = await client.send(getCommand)
      if (!secretResponse.SecretString) {
        console.warn(`No secret string found for ${secretName}`)
        continue
      }

      const secretData = JSON.parse(secretResponse.SecretString)

      // Check if the secret has the required fields
      if (!secretData.seed) {
        console.warn(`Skipping tenant ${tenantName} without seed property`)
        continue
      }

      // Add the tenant to the valid tenants list
      validTenants.push({
        name: tenantName,
        didSeed: secretData.seed,
        didMethod: 'key', // Default to 'key' method
        cryptosuite: secretData.cryptosuite,
        authToken: secretData.authToken
      })
    }

    return validTenants
  } catch (error) {
    console.error('Error fetching tenants from AWS Secrets Manager:', error)
    return null
  }
}

export function setConfig() {
  CONFIG = parseConfig()
}

export async function fetchAndUpdateTenantSeeds() {
  const tenants = await getTenantsFromAwsSecretsManager()
  if (tenants && tenants.length > 0) {
    for (const tenant of tenants) {
      const didSeed = await decodeSeed(tenant.didSeed)
      DID_SEEDS[tenant.name] = {
        keyMaterial: ed25519SeedMaterial(didSeed),
        didSeed,
        didMethod: 'key',
        cryptosuite: tenant.cryptosuite,
        authToken: tenant.authToken
      }
    }
    // add in the default test key now, so it can be overridden by env
    DID_SEEDS[TEST_TENANT_NAME] = {
      keyMaterial: ed25519SeedMaterial(await decodeSeed(testSeed)),
      didSeed: await decodeSeed(testSeed),
      didMethod: 'key'
    }
    // and again with a different tenant name
    DID_SEEDS[SECOND_TEST_TENANT_NAME] = {
      keyMaterial: ed25519SeedMaterial(await decodeSeed(testSeed)),
      didSeed: await decodeSeed(testSeed),
      didMethod: 'key'
    }
    rebuildTokenToTenantMap()
    return // Skip the environment variable processing if tenants were loaded from URL
  }

  // If TENANTS_API_URL is not set or failed, continue with default and environment variable processing
  // add in the default test key now, so it can be overridden by env
  DID_SEEDS[TEST_TENANT_NAME] = {
    keyMaterial: ed25519SeedMaterial(await decodeSeed(testSeed)),
    didSeed: await decodeSeed(testSeed),
    didMethod: 'key'
  }
  // and again with a different tenant name
  DID_SEEDS[SECOND_TEST_TENANT_NAME] = {
    keyMaterial: ed25519SeedMaterial(await decodeSeed(testSeed)),
    didSeed: await decodeSeed(testSeed),
    didMethod: 'key'
  }
  // also add in the random test key
  const randomSeed = { didSeed: await generateSecretKeySeed() }
  DID_SEEDS[randomTenantName] = await decodeSeed(randomSeed.didSeed)
  const allEnvVars = process.env
  for (const { tenant, seedEnvKey } of discoverTenants(allEnvVars)) {
    const tenantName = tenant.toLowerCase()
    const cryptosuite = process.env[`TENANT_CRYPTOSUITE_${tenant}`]
    const publicKeyMultibase =
      process.env[`${TENANT_KEY_PUBLIC_PREFIX}${tenant}`]
    const secretKeyMultibase =
      process.env[`${TENANT_KEY_SECRET_PREFIX}${tenant}`]

    // Shape first, values second. An ambiguous or half-written declaration is
    // refused before anything is decoded, so the operator gets a message about
    // the variables they wrote rather than one from inside a crypto library.
    const kind = classifyTenantKeyMaterial({
      tenant,
      cryptosuite,
      seed: seedEnvKey ? allEnvVars[seedEnvKey] : undefined,
      publicKeyMultibase,
      secretKeyMultibase
    })

    let keyMaterial
    if (kind === KEY_MATERIAL_MULTIKEY) {
      keyMaterial = multikeyMaterial({ publicKeyMultibase, secretKeyMultibase })
    } else {
      let value = allEnvVars[seedEnvKey]
      if (value === 'generate') {
        value = await generateSecretKeySeed()
      }
      keyMaterial = ed25519SeedMaterial(await decodeSeed(value))
    }

    DID_SEEDS[tenantName] = {
      keyMaterial,
      // The decoded seed, still on the entry, for the did:web driver and the
      // Ed25519 signing paths that take one directly. Undefined for an ECDSA
      // tenant, which has no seed at all — `keyMaterial` is what every caller
      // should test a tenant's existence on.
      didSeed: keyMaterial.seed,
      didMethod:
        process.env[`TENANT_DIDMETHOD_${tenant}`] &&
        process.env[`TENANT_DIDMETHOD_${tenant}`].toLowerCase() === 'web'
          ? 'web'
          : 'key',
      didUrl: process.env[`TENANT_DID_URL_${tenant}`],
      cryptosuite,
      authToken: process.env[`TENANT_AUTH_TOKEN_${tenant}`]
    }
  }
  rebuildTokenToTenantMap()
}

/**
 * Finds every tenant declared in the environment.
 *
 * ⚠️ **The tenant set is the UNION of the key-material families, not the
 * `TENANT_SEED_` family alone.** This filtered on `TENANT_SEED_` until ECDSA
 * tenants existed, which meant a tenant carrying only `TENANT_KEY_PUBLIC_<T>` /
 * `TENANT_KEY_SECRET_<T>` was *invisible* rather than merely unsigned: no
 * refusal, no warning, a 404 at issuance and nothing to explain it.
 * `TENANT_KEY_SECRET_` is included as a discovery family too, even though a
 * complete ECDSA tenant always declares the public half — otherwise a
 * secret-only declaration would vanish instead of hitting the half-a-pair
 * refusal, which is the same disappearing act one variable over.
 *
 * ⚠️ **The suffix is sliced raw and case-preserved**, then interpolated into
 * `TENANT_CRYPTOSUITE_${tenant}` and its siblings — so a mixed-case tenant name
 * silently yields `cryptosuite: undefined`. Long-standing behaviour, preserved
 * deliberately rather than fixed here; provisioning uses one uppercase suffix
 * everywhere. The seed's *own* env key is carried through rather than
 * reconstructed, for the same reason: the filter matches case-insensitively but
 * `process.env` does not.
 *
 * @param {object} allEnvVars - Normally `process.env`.
 * @returns {Array<{tenant: string, seedEnvKey?: string}>} One entry per raw
 *   suffix, in the order the environment first mentions it.
 */
function discoverTenants(allEnvVars) {
  const bySuffix = new Map()
  const slotFor = (suffix) => {
    if (!bySuffix.has(suffix)) bySuffix.set(suffix, { tenant: suffix })
    return bySuffix.get(suffix)
  }

  for (const key of Object.getOwnPropertyNames(allEnvVars)) {
    const upper = key.toUpperCase()
    if (upper.startsWith(TENANT_SEED_PREFIX)) {
      slotFor(key.slice(TENANT_SEED_PREFIX.length)).seedEnvKey = key
    } else if (upper.startsWith(TENANT_KEY_PUBLIC_PREFIX)) {
      slotFor(key.slice(TENANT_KEY_PUBLIC_PREFIX.length))
    } else if (upper.startsWith(TENANT_KEY_SECRET_PREFIX)) {
      slotFor(key.slice(TENANT_KEY_SECRET_PREFIX.length))
    }
  }

  return [...bySuffix.values()]
}

function parseConfig() {
  const env = process.env
  const config = Object.freeze({
    port: env.PORT ? parseInt(env.PORT) : defaultPort,
    enableHttpsForDev: env.ENABLE_HTTPS_FOR_DEV?.toLowerCase() === 'true',
    enableAccessLogging: env.ENABLE_ACCESS_LOGGING?.toLowerCase() === 'true',
    consoleLogLevel:
      env.CONSOLE_LOG_LEVEL?.toLocaleLowerCase() || defaultConsoleLogLevel,
    logLevel: env.LOG_LEVEL?.toLocaleLowerCase() || defaultLogLevel,
    errorLogFile: env.ERROR_LOG_FILE,
    logAllFile: env.LOG_ALL_FILE
  })
  return config
}

export function getConfig() {
  if (!CONFIG) {
    setConfig()
  }
  return CONFIG
}

export function resetConfig() {
  CONFIG = null
  DID_SEEDS = {}
  TOKEN_TO_TENANT.clear()
}

/* for testing, to allow testing broken calls */
export async function deleteSeed(tenantName) {
  delete DID_SEEDS[tenantName]
  rebuildTokenToTenantMap()
}

/**
 * Loads tenant seeds from env / AWS if not already loaded (e.g. before Bearer token lookup).
 */
export async function ensureTenantSeedsLoaded() {
  if (!Object.keys(DID_SEEDS).length) {
    await fetchAndUpdateTenantSeeds()
  }
}

export async function getTenantSeed(tenantName) {
  await ensureTenantSeedsLoaded()
  return DID_SEEDS[tenantName] ?? null
}

/*

DID doc for tenant test with seed z1AeiPT496wWmo9BG2QYXeTusgFSZPNG3T9wNeTtjrQ3rCB
{
  '@context': [
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/suites/ed25519-2020/v1',
    'https://w3id.org/security/suites/x25519-2020/v1'
  ],
  id: 'did:key:z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q',
  verificationMethod: [
    {
      id: 'did:key:z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q#z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q',
      type: 'Ed25519VerificationKey2020',
      controller: 'did:key:z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q',
      publicKeyMultibase: 'z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q'
    }
  ],
  authentication: [
    'did:key:z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q#z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q'
  ],
  assertionMethod: [
    'did:key:z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q#z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q'
  ],
  capabilityDelegation: [
    'did:key:z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q#z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q'
  ],
  capabilityInvocation: [
    'did:key:z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q#z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q'
  ],
  keyAgreement: [
    {
      id: 'did:key:z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q#z6LStW7uovRREdrMqg33zVSU64GRsWhz2U9U3JHAdGtHYxz3',
      type: 'X25519KeyAgreementKey2020',
      controller: 'did:key:z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q',
      publicKeyMultibase: 'z6LStW7uovRREdrMqg33zVSU64GRsWhz2U9U3JHAdGtHYxz3'
    }
  ]
}

*/
