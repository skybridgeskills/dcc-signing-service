import { expect } from 'chai'
import jsonld from 'jsonld'
import { securityLoader } from '@digitalcredentials/security-document-loader'
import { addPinnedContexts, PINNED_CONTEXTS } from './index.js'
import {
  IDENTIFICATION_V1RC1_CONTEXT,
  IDENTIFICATION_V1RC1_CONTEXT_URL
} from './identification-v1rc1.js'
import { getUnsignedIdentificationDocument } from '../test-fixtures/vc.js'
import { withFetchBlocked } from '../test-fixtures/network.js'

// Built exactly as `src/issue.js` builds the signing loader.
const buildLoader = () => addPinnedContexts(securityLoader()).build()

describe('pinned JSON-LD contexts', () => {
  it('registers the identification v1rc1 context', () => {
    expect(PINNED_CONTEXTS.get(IDENTIFICATION_V1RC1_CONTEXT_URL)).to.equal(
      IDENTIFICATION_V1RC1_CONTEXT
    )
  })

  it('is what the bundled loader alone cannot serve', async () => {
    // The regression this directory exists for: without the pin, the loader
    // has no network path and no copy. If this starts failing after a
    // `security-document-loader` upgrade, the bundled set has caught up —
    // compare the two documents and drop the pin rather than shadow it.
    let error
    try {
      await securityLoader().build()(IDENTIFICATION_V1RC1_CONTEXT_URL)
    } catch (e) {
      error = e
    }
    expect(error?.message).to.have.string(IDENTIFICATION_V1RC1_CONTEXT_URL)
  })

  it('resolves every pinned context from memory, with the network blocked', async () => {
    const loader = buildLoader()
    const attempts = await withFetchBlocked(async () => {
      for (const [url, document] of PINNED_CONTEXTS) {
        const result = await loader(url)
        expect(result.documentUrl).to.eql(url)
        expect(result.document).to.eql(document)
      }
    })
    expect(attempts).to.eql([])
  })

  it('covers every term the identification document credential emits', async () => {
    // `safe: true` alone does NOT prove coverage here. It throws on a dropped
    // term, but the VC 2.0 context declares an `@vocab`
    // (`https://www.w3.org/ns/credentials/issuer-dependent#`), so under it an
    // undefined term is never dropped — it silently becomes an issuer-dependent
    // IRI and canonizes fine. Checked: a misspelt `documentNumber` passes safe
    // mode. So this asserts the IRIs the vendored context is supposed to
    // supply, and that nothing fell through to the `@vocab` fallback.
    const nquads = await jsonld.toRDF(getUnsignedIdentificationDocument(), {
      format: 'application/n-quads',
      safe: true,
      documentLoader: buildLoader()
    })
    for (const iri of [
      'https://schema.org/givenName',
      'https://schema.org/familyName',
      'https://schema.org/birthDate',
      'https://w3id.org/identification#identificationDocument',
      'https://w3id.org/identification#documentIdentifier'
    ]) {
      expect(nquads).to.have.string(`<${iri}>`)
    }
    expect(nquads).to.not.have.string('credentials/issuer-dependent#')
  })

  // Drift: the vendored copy must still match what the URL serves. Skips —
  // never fails — when the network is unavailable, so CI without egress and a
  // developer offline stay green; an outage upstream is not a defect here.
  it('still matches the published identification v1rc1 document', async function () {
    let response
    try {
      response = await fetch(IDENTIFICATION_V1RC1_CONTEXT_URL, {
        headers: { Accept: 'application/ld+json' },
        signal: AbortSignal.timeout(8000)
      })
    } catch (e) {
      this.skip()
    }
    if (response.status >= 500) this.skip()
    expect(response.ok, `HTTP ${response.status}`).to.eql(true)
    const published = await response.json()
    expect(
      published,
      'The published context has changed. Re-vendor src/contexts/identification-v1rc1.js ' +
        'and update its provenance header — a signature covers these bytes.'
    ).to.eql(IDENTIFICATION_V1RC1_CONTEXT)
  })
})
