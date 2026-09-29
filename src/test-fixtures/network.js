/**
 * Runs `fn` with `fetch` replaced by one that records every attempt and
 * refuses it, so a test can prove it made no network request rather than
 * assume it. Signing must never fetch a JSON-LD context — see
 * docs/adr/2026-09-29-signing-pins-jsonld-contexts.md.
 *
 * @param {Function} fn - Async work to run with the network blocked.
 * @returns {Promise<string[]>} The URLs something tried to fetch.
 */
export const withFetchBlocked = async (fn) => {
  const realFetch = global.fetch
  const attempts = []
  global.fetch = async (url) => {
    attempts.push(String(url))
    throw new Error(`network access blocked in test: ${url}`)
  }
  try {
    await fn()
  } finally {
    global.fetch = realFetch
  }
  return attempts
}
