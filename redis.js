import Redis from 'ioredis'

const redis = new Redis(process.env.REDIS_URI ?? 'localhost:6379')

export async function allTenants() {
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
