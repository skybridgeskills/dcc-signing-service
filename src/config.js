import { generateSecretKeySeed } from 'bnid'
import {
  SecretsManagerClient,
  GetSecretValueCommand,
  ListSecretsCommand
} from '@aws-sdk/client-secrets-manager'
import decodeSeed from './utils/decodeSeed.js'

let CONFIG
const defaultPort = 4006
const defaultConsoleLogLevel = 'silly'
const defaultLogLevel = 'silly'
const testSeed = 'z1AeiPT496wWmo9BG2QYXeTusgFSZPNG3T9wNeTtjrQ3rCB'
export const TEST_TENANT_NAME = 'testing'
export const SECOND_TEST_TENANT_NAME = 'test'
const randomTenantName = 'random'
let DID_SEEDS = {}

async function getTenantsFromAwsSecretsManager() {
  if (!process.env.TENANTS_AWS_SECRETS) {
    return null
  }
  console.log('Attempting to get tenants from AWS Secrets Manager')

  try {
    const client = new SecretsManagerClient({
      region: process.env.AWS_REGION || 'us-west-2'
    })

    // List all secrets with the tenant/ prefix
    const listCommand = new ListSecretsCommand({
      Filters: [
        {
          Key: 'name',
          Values: ['tenant/']
        }
      ]
    })

    const listResponse = await client.send(listCommand)
    if (!listResponse.SecretList || listResponse.SecretList.length === 0) {
      console.log('No tenant secrets found in AWS Secrets Manager')
      return null
    }

    const validTenants = []

    // Process each tenant secret
    for (const secret of listResponse.SecretList) {
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
        didMethod: 'key' // Default to 'key' method
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
      DID_SEEDS[tenant.name] = {
        didSeed: await decodeSeed(tenant.didSeed),
        didMethod: 'key'
      }
    }
    // add in the default test key now, so it can be overridden by env
    DID_SEEDS[TEST_TENANT_NAME] = {
      didSeed: await decodeSeed(testSeed),
      didMethod: 'key'
    }
    // and again with a different tenant name
    DID_SEEDS[SECOND_TEST_TENANT_NAME] = {
      didSeed: await decodeSeed(testSeed),
      didMethod: 'key'
    }
    return // Skip the environment variable processing if tenants were loaded from URL
  }

  // If TENANTS_API_URL is not set or failed, continue with default and environment variable processing
  // add in the default test key now, so it can be overridden by env
  DID_SEEDS[TEST_TENANT_NAME] = {
    didSeed: await decodeSeed(testSeed),
    didMethod: 'key'
  }
  // and again with a different tenant name
  DID_SEEDS[SECOND_TEST_TENANT_NAME] = {
    didSeed: await decodeSeed(testSeed),
    didMethod: 'key'
  }
  // also add in the random test key
  const randomSeed = { didSeed: await generateSecretKeySeed() }
  DID_SEEDS[randomTenantName] = await decodeSeed(randomSeed.didSeed)
  const allEnvVars = process.env
  const didSeedKeys = Object.getOwnPropertyNames(allEnvVars).filter((key) =>
    key.toUpperCase().startsWith('TENANT_SEED_')
  )
  for (const key of didSeedKeys) {
    let value = allEnvVars[key]
    if (value === 'generate') {
      value = await generateSecretKeySeed()
    }
    const tenant = key.slice(12)
    const tenantName = tenant.toLowerCase()
    DID_SEEDS[tenantName] = {
      didSeed: await decodeSeed(value),
      didMethod:
        process.env[`TENANT_DIDMETHOD_${tenant}`] &&
        process.env[`TENANT_DIDMETHOD_${tenant}`].toLowerCase() === 'web'
          ? 'web'
          : 'key',
      didUrl: process.env[`TENANT_DID_URL_${tenant}`]
    }
  }
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
}

/* for testing, to allow testing broken calls */
export async function deleteSeed(tenantName) {
  delete DID_SEEDS[tenantName]
}

export async function getTenantSeed(tenantName) {
  if (!Object.keys(DID_SEEDS).length) {
    await fetchAndUpdateTenantSeeds()
  }
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
