import SigningException from '../SigningException.js'
import { getTenantSeed } from '../config.js'

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
 * Middleware to authenticate Bearer token or Basic Auth for VCALM endpoint.
 * Validates the Authorization header against the tenant's configured auth token.
 *
 * @param {object} req - Express request object
 * @param {object} res - Express response object
 * @param {function} next - Express next function
 */
export async function authenticateBearerToken(req, res, next) {
  const instanceId = req.params.instanceId
  const authHeader = req.headers.authorization

  const tenantConfig = await getTenantSeed(instanceId)

  if (!tenantConfig) {
    return next(new SigningException(404, "Tenant doesn't exist."))
  }

  // If no auth token is configured for the tenant, skip authentication entirely
  if (!tenantConfig.authToken) {
    return next()
  }

  // Tenant has auth token configured, so require authentication
  if (!authHeader) {
    return next(new SigningException(401, 'Authorization header required'))
  }

  const [scheme] = authHeader.split(' ')

  // Handle Basic Auth
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

    // For Basic Auth, username should be the tenant name (instanceId)
    // and password should be the tenant's authToken
    if (credentials.username !== instanceId) {
      return next(new SigningException(401, 'Invalid username'))
    }

    if (credentials.password !== tenantConfig.authToken) {
      return next(new SigningException(401, 'Invalid password'))
    }

    return next()
  }

  // Handle Bearer Auth
  if (scheme === 'Bearer') {
    const [, token] = authHeader.split(' ')

    if (!token) {
      return next(
        new SigningException(401, 'Invalid Bearer format. Use: Bearer <token>')
      )
    }

    if (token !== tenantConfig.authToken) {
      return next(new SigningException(401, 'Invalid token'))
    }

    return next()
  }

  // Unknown scheme
  return next(
    new SigningException(
      401,
      'Invalid authorization format. Use: Basic <base64(username:password)> or Bearer <token>'
    )
  )
}
