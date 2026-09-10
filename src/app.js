import express from 'express'
import cors from 'cors'
import axios from 'axios'
import issue from './issue.js'
import generateSeed from './generate.js'
import accessLogger from './middleware/accessLogger.js'
import errorHandler from './middleware/errorHandler.js'
import errorLogger from './middleware/errorLogger.js'
import invalidPathHandler from './middleware/invalidPathHandler.js'
import { authenticateAndIdentifyTenant } from './middleware/auth.js'
import SigningException from './SigningException.js'
import { getTenantDidDocument } from './didWeb.js'
import signRequestObject, {
  REQUEST_OBJECT_JWT_MEDIA_TYPE
} from './signRequestObject.js'
import { getUnsignedVC } from './test-fixtures/vc.js'
import { TEST_TENANT_NAME, fetchAndUpdateTenantSeeds } from './config.js'

export async function build() {
  var app = express()

  // Add middleware to write http access logs
  app.use(accessLogger())
  app.use(express.json())
  app.use(express.urlencoded({ extended: false }))
  app.use(cors())

  app.get('/healthz', async function (req, res) {
    try {
      const { data } = await axios.post(
        `${req.protocol}://${req.headers.host}/instance/${TEST_TENANT_NAME}/credentials/sign`,
        getUnsignedVC()
      )
      if (!data.proof)
        throw new SigningException(503, 'signing-service healthz failed')
    } catch (e) {
      console.log(`exception in healthz: ${JSON.stringify(e)}`)
      return res.status(503).json({
        error: `signing-service healthz check failed with error: ${e}`,
        healthy: false
      })
    }
    res.send({ message: 'signing-service server status: ok.', healthy: true })
  })

  app.get('/', function (req, res) {
    res.send({ message: 'signing-service server status: ok.' })
  })

  app.post('/instance/:instanceId/credentials/sign', async (req, res, next) => {
    try {
      const instanceId = req.params.instanceId //the issuer instance/tenant with which to sign
      const unSignedVC = req.body
      if (!req.body || !Object.keys(req.body).length) {
        throw new SigningException(
          400,
          'A verifiable credential must be provided in the body.'
        )
      }
      const signedVC = await issue(unSignedVC, instanceId)
      return res.json(signedVC)
    } catch (e) {
      // catch the async errors and pass them to the error logger and handler
      next(e)
    }
  })

  // VCALM-compatible issue endpoint with authentication
  app.post(
    '/credentials/issue',
    authenticateAndIdentifyTenant,
    async (req, res, next) => {
      try {
        const instanceId = req.identifiedTenantId
        const { credential } = req.body

        if (!credential || !Object.keys(credential).length) {
          throw new SigningException(
            400,
            'A verifiable credential must be provided in the credential property.'
          )
        }

        const signedVC = await issue(credential, instanceId)
        return res.json(signedVC)
      } catch (e) {
        next(e)
      }
    }
  )

  /**
   * Publish a `did:web` tenant's DID document.
   *
   * Deliberately unauthenticated: a DID document is public by definition — it
   * is the thing every verifier on earth is expected to fetch — and it carries
   * only public key material. The tenant name is already in the URL the caller
   * constructed, so the 404 for a `did:key` tenant leaks nothing either.
   *
   * The bytes are derived from the tenant's seed on every request rather than
   * stored anywhere (see `didWeb.js`), so the published document cannot drift
   * from the key that signs. That is the whole reason this endpoint exists
   * instead of a checked-in `did.json`. The driver's output is re-expressed in
   * the conventional shape on the way out — a move, never a re-composition;
   * see `normaliseDidDocument`.
   *
   * `dcc-transaction-service` proxies this at the identifier's own URL, since
   * the authority in `did:web:<host>:...` is the tunnelled host it answers on,
   * not this service.
   */
  /**
   * Sign an OID4VP authorization request object with a tenant's existing key.
   *
   * ⚠️ **Not a credential**, and deliberately in this service anyway: the
   * `decentralized_identifier` Client Identifier Prefix needs the JOSE `kid` to
   * name a key in the published DID document, and this is the only component
   * that derives both from one seed. See `signRequestObject.js`.
   *
   * Returns the compact JWS as the body, not wrapped in JSON — the caller
   * serves these bytes verbatim at its `request_uri`, and anything around them
   * would have to be unwrapped first.
   */
  app.post(
    '/instance/:instanceId/openid4vp/request-object/sign',
    async (req, res, next) => {
      try {
        const jws = await signRequestObject(req.body, req.params.instanceId)
        res.type(REQUEST_OBJECT_JWT_MEDIA_TYPE)
        return res.send(jws)
      } catch (e) {
        next(e)
      }
    }
  )

  app.get('/instance/:instanceId/did.json', async (req, res, next) => {
    try {
      const didDocument = await getTenantDidDocument(req.params.instanceId)
      // A plain DID document, no envelope: the caller is a DID resolver (or a
      // proxy in front of one) and anything wrapping it would have to be
      // unwrapped by every one of them.
      res.type('application/json')
      return res.json(didDocument)
    } catch (e) {
      next(e)
    }
  })

  app.get('/refresh-seeds', async (_, res) => {
    await fetchAndUpdateTenantSeeds()
    console.log('refreshing...')
    res.json({ message: 'DID seeds refreshed' })
  })

  app.get('/did-key-generator', async (req, res, next) => {
    try {
      const newSeed = await generateSeed({})
      res.json(newSeed)
    } catch (e) {
      next(e)
    }
  })

  app.post('/did-web-generator', async (req, res, next) => {
    try {
      const { url } = req.body
      const newSeed = await generateSeed({ url })
      res.json(newSeed)
    } catch (e) {
      next(e)
    }
  })

  // Attach the error handling middleware calls, in the order that they should run
  app.use(errorLogger)
  app.use(errorHandler)
  app.use(invalidPathHandler)

  return app
}
