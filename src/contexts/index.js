import {
  IDENTIFICATION_V1RC1_CONTEXT,
  IDENTIFICATION_V1RC1_CONTEXT_URL
} from './identification-v1rc1.js'

/**
 * JSON-LD contexts this service pins locally, beyond the set bundled with
 * `@digitalcredentials/security-document-loader`.
 *
 * Adding a context here is the ONLY way this service can sign a credential that
 * carries it. Signing performs no context fetch — see
 * docs/adr/2026-09-29-signing-pins-jsonld-contexts.md. To add one, vendor the
 * document as a sibling module with its provenance header (copy
 * `identification-v1rc1.js`), list it here, and add it to the cases in
 * `contexts.test.js`.
 */
export const PINNED_CONTEXTS = new Map([
  [IDENTIFICATION_V1RC1_CONTEXT_URL, IDENTIFICATION_V1RC1_CONTEXT]
])

/**
 * Registers every pinned context on a `securityLoader()` instance, BEFORE
 * `.build()`.
 *
 * Statics are consulted ahead of any protocol handler in
 * `jsonld-document-loader`, so a pinned document wins outright — this is not a
 * fallback behind a fetch.
 *
 * @param {object} loader - The unbuilt loader `securityLoader()` returns.
 * @returns {object} The same loader, for chaining into `.build()`.
 */
export function addPinnedContexts(loader) {
  for (const [url, document] of PINNED_CONTEXTS) {
    loader.addStatic(url, document)
  }
  return loader
}
