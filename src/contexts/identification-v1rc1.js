/**
 * The `https://w3id.org/identification/v1rc1` JSON-LD context, vendored.
 *
 * WHY THIS FILE EXISTS. This service's document loader is built with
 * `fetchRemoteContexts` off, which does not mean "fetch slowly" — it means the
 * http/https protocol handlers are never registered and there is no network
 * path at all. A credential carrying any context outside
 * `@digitalcredentials/security-document-loader`'s bundled set therefore cannot
 * be signed. That is deliberate: see
 * docs/adr/2026-09-29-signing-pins-jsonld-contexts.md.
 *
 * This context is the first one outside that bundled set this service has
 * been asked to sign under: the `identification_document_v1rc1` profile in
 * skybridgeskills-monorepo. Before it was pinned here, every such credential
 * failed during canonization with jsonld's "Dereferencing a URL did not result
 * in a valid JSON-LD object", which names no URL.
 *
 * PROVENANCE — this is a verbatim copy, not a transcription. Do not edit it by
 * hand; re-fetch and replace the whole document, and update these four lines.
 *   Source URL:   https://w3id.org/identification/v1rc1
 *   Resolves to:  https://digitalbazaar.github.io/identification-vocab/contexts/v1rc1.jsonld
 *   sha256:       af65e5177a2f82ee0a332e4c32a0c0887988858d464ad83359846f573a897144
 *                 (of the 3460 bytes served, not of the literal below)
 *   Fetched:      2026-09-29
 *
 * The literal below is those bytes parsed and re-serialised, so its own hash
 * will not match the one above. `contexts.test.js` checks for drift by
 * deep-equality of parsed documents, which is the comparison that means
 * something; the sha256 is for a human comparing a fresh fetch by hand.
 *
 * `v1rc1` is a release candidate. If it goes final, the `v1` URL is a NEW
 * context and a new profile version in skybridgeskills-monorepo — not an edit
 * to this file.
 */
export const IDENTIFICATION_V1RC1_CONTEXT_URL =
  'https://w3id.org/identification/v1rc1'

export const IDENTIFICATION_V1RC1_CONTEXT = {
  '@context': {
    '@protected': true,
    id: '@id',
    type: '@type',
    name: 'https://schema.org/name',
    IdentificationDocumentCredential:
      'https://w3id.org/identification#IdentificationDocumentCredential',
    IdentificationDocument: {
      '@id': 'https://w3id.org/identification#IdentificationDocument',
      '@context': {
        '@protected': true,
        id: '@id',
        type: '@type',
        aamvaDhsCompliance: 'https://w3id.org/vdl/aamva#dhsCompliance',
        aamvaDhsComplianceText: 'https://w3id.org/vdl/aamva#dhsCompliance_text',
        aamvaDomesticDrivingPrivileges: {
          '@id': 'https://w3id.org/vdl/aamva#domesticDrivingPrivileges',
          '@type': '@json'
        },
        documentIdentifier:
          'https://w3id.org/identification#documentIdentifier',
        issuer: {
          '@id': 'https://www.w3.org/2018/credentials#issuer',
          '@type': '@id'
        },
        restrictions: 'https://w3id.org/identification#restrictions',
        validFrom: {
          '@id': 'https://www.w3.org/2018/credentials#validFrom',
          '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'
        },
        validUntil: {
          '@id': 'https://www.w3.org/2018/credentials#validUntil',
          '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'
        }
      }
    },
    Observation: {
      '@id': 'https://schema.org/Observation',
      '@context': {
        '@protected': true,
        id: '@id',
        type: '@type',
        description: 'https://schema.org/description',
        observationDate: {
          '@id': 'https://schema.org/observationDate',
          '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'
        },
        unitCode: 'https://schema.org/unitCode',
        value: {
          '@id': 'https://schema.org/value',
          '@type': 'http://www.w3.org/2001/XMLSchema#unsignedInt'
        },
        variableMeasured: 'https://schema.org/variableMeasured'
      }
    },
    PostalAddress: {
      '@id': 'https://schema.org/PostalAddress',
      '@context': {
        '@protected': true,
        id: '@id',
        type: '@type',
        streetAddress: 'https://schema.org/streetAddress',
        addressRegion: 'https://schema.org/addressRegion',
        addressLocality: 'https://schema.org/addressLocality',
        addressCountry: 'https://schema.org/addressCountry',
        postalCode: 'https://schema.org/postalCode'
      }
    },
    Person: {
      '@id': 'https://schema.org/Person',
      '@context': {
        '@protected': true,
        id: '@id',
        type: '@type',
        additionalName: 'https://schema.org/additionalName',
        address: 'https://schema.org/address',
        birthDate: {
          '@id': 'https://schema.org/birthDate',
          '@type': 'https://schema.org/Date'
        },
        email: 'https://schema.org/email',
        eyeColor: 'https://w3id.org/vdl#eyeColour',
        familyName: 'https://schema.org/familyName',
        givenName: 'https://schema.org/givenName',
        height: 'https://schema.org/height',
        hairColor: 'https://w3id.org/vdl#hairColour',
        identificationDocument:
          'https://w3id.org/identification#identificationDocument',
        image: 'https://schema.org/image',
        telephone: 'https://schema.org/telephone',
        weight: 'https://schema.org/weight'
      }
    }
  }
}
