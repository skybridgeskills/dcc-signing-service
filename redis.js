import Redis from 'ioredis'

const redis = process.env.TENANT_SEED_TESTING
  ? null
  : new Redis(process.env.REDIS_URI ?? 'localhost:6379')

export async function allTenants() {
  if (process.env.TENANT_SEED_TESTING) return []
  const keys = await redis.keys('tenantPrivate:*')
  const toTenant = async (key) => {
    const seed = await redis.hget(key, 'seed')
    return {
      name: key,
      didSeed: seed,
      didMethod: 'key'
    }
  }
  const tenants = await Promise.all(keys.map(toTenant))
  return tenants
}
