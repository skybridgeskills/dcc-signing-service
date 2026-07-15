import SigningException from '../SigningException.js'
import {
  getTenantSeed,
  getTenantByToken,
  ensureTenantSeedsLoaded
} from '../config.js'

/**
 * Parses Basic Auth credentials from Authorization header.
 *
 * @param {string} authHeader - The Authorization header value
 * @returns {object|null} Object with username and password, or null if invalid
 */
function parseBasicAuth(authHeader) {
  const [scheme, encoded] = authHeader.split(' ')

  if (scheme !== 'Basic' || !encoded) {
    return null
  }

  try {
    const decoded = Buffer.from(encoded, 'base64').toString('utf8')
    const [username, password] = decoded.split(':')

    if (!username || password === undefined) {
      return null
    }

    return { username, password }
  } catch {
    return null
  }
}

/**
 * Middleware for POST /credentials/issue: identify the tenant from Basic Auth
 * (username = tenant name) or Bearer token (reverse lookup), then authenticate.
 *
 * Tenants without TENANT_AUTH_TOKEN accept Basic Auth with any password once the
 * tenant name in the username matches; Bearer is only available when a token is
 * configured (unique per tenant).
 *
 * @param {object} req - Express request object
 * @param {object} res - Express response object
 * @param {function} next - Express next function
 */
export async function authenticateAndIdentifyTenant(req, res, next) {
  await ensureTenantSeedsLoaded()

  const authHeader = req.headers.authorization

  if (!authHeader) {
    return next(new SigningException(401, 'Authorization header required'))
  }

  const [scheme] = authHeader.split(' ')

  if (scheme === 'Basic') {
    const credentials = parseBasicAuth(authHeader)

    if (!credentials) {
      return next(
        new SigningException(
          401,
          'Invalid Basic Auth format. Use: Basic <base64(username:password)>'
        )
      )
    }

    const instanceId = credentials.username.toLowerCase()
    const tenantConfig = await getTenantSeed(instanceId)

    if (!tenantConfig) {
      return next(new SigningException(404, "Tenant doesn't exist."))
    }

    if (
      tenantConfig.authToken &&
      credentials.password !== tenantConfig.authToken
    ) {
      return next(new SigningException(401, 'Invalid password'))
    }

    req.identifiedTenantId = instanceId
    return next()
  }

  if (scheme === 'Bearer') {
    const [, token] = authHeader.split(' ')

    if (!token) {
      return next(
        new SigningException(401, 'Invalid Bearer format. Use: Bearer <token>')
      )
    }

    const instanceId = getTenantByToken(token)
    if (!instanceId) {
      return next(new SigningException(401, 'Invalid token'))
    }

    const tenantConfig = await getTenantSeed(instanceId)
    if (!tenantConfig || tenantConfig.authToken !== token) {
      return next(new SigningException(401, 'Invalid token'))
    }

    req.identifiedTenantId = instanceId
    return next()
  }

  return next(
    new SigningException(
      401,
      'Invalid authorization format. Use: Basic <base64(username:password)> or Bearer <token>'
    )
  )
}
