# ADR: Signing pins the JSON-LD contexts it will sign under, and refuses an unpinned one by name

**Date:** 2026-09-29
**Status:** Accepted
**Related work:** `fix/identification-context`; the `identification_document_v1rc1` credential
profile in `skybridgeskills-monorepo`; `dcc-transaction-service`
`src/lib/verifier-document-loader.ts` and `verifier-core`
`src/util/document-loader-from-http-get.ts`, which build the same loader with the opposite
setting.

## Context

Signing an `identification_document_v1rc1` credential through
`POST /instance/:instanceId/credentials/sign` failed in canonization, before any signature was
computed:

> An error occurred in the signing-service: Dereferencing a URL did not result in a valid
> JSON-LD object… `jsonld.InvalidUrl` at `ContextResolver._fetchContext`

The credential's second context is `https://w3id.org/identification/v1rc1`. That URL is
fine: it redirects once to GitHub Pages and serves valid `application/ld+json`. **The service
refused to go and get it.** `src/issue.js` built its loader as `securityLoader().build()`, and
`@digitalcredentials/security-document-loader@6.0.1` defaults `fetchRemoteContexts` to
`false` — in which mode it never registers the http/https protocol handlers. That is not a
loader with a slow network path; it is a loader with no network path. It serves a fixed
bundled set: VC 1.1 and 2.0, DID core, the Ed25519/X25519 2020 suites, data integrity, the DCC
context, both status-list contexts and every published Open Badges v3 context.

Open Badge issuance never hit this because `purl.imsglobal.org/spec/ob/v3p0/…` is in that
set. `identification_document_v1rc1` is the first profile this service has been asked to sign
under a context outside it — and nothing upstream could have caught it, because
`skybridgeskills-monorepo` never signs for real in test (its signing service is a stub that
does no JSON-LD work).

**The failure was also unreadable.** The loader threw a precise error —
`Document not found in document loader: https://w3id.org/identification/v1rc1` — and
`jsonld`'s `ContextResolver._fetchContext` (`lib/ContextResolver.js:173`) caught it and
rethrew it under a fixed message that names no URL and lists four possible causes (same-origin
policy, redirects, a non-JSON response, Link headers), none of which was the real one. The
URL and the loader's error survive only in the `JsonLdError`'s `details`, which neither its
message nor its stack carries — and message and stack are all this service's `errorLogger`
writes. So the URL reached no log at all. That lost URL was most of what made the incident
expensive to diagnose.

Two sibling services build the same loader with `fetchRemoteContexts: true`, so an identity
document already **verifies**. Only signing was blocked.

## Decision 1 — signing pins contexts and performs no context fetch

**This service resolves every JSON-LD context from memory.** A context outside the loader's
bundled set is vendored into `src/contexts/` and registered on the loader with `addStatic`
before it is built. `fetchRemoteContexts` stays off, and no protocol handler is added.

- **A registry, not a call.** `src/contexts/index.js` exports `PINNED_CONTEXTS`, a map from
  URL to document, and `addPinnedContexts(loader)`. The next profile that brings a context is
  a one-line addition to a list, not a rediscovery of this bug.
- **Verbatim, with provenance.** Each vendored module carries its source URL, the URL it
  resolved to, the sha256 of the bytes served and the fetch date in a header comment.
- **Tested for drift.** `src/contexts/contexts.test.js` re-fetches each published document and
  deep-compares it with the vendored copy, and **skips** — never fails — when the network is
  unavailable. It compares parsed documents rather than hashes because the module literal is
  a re-serialisation; the sha256 is provenance for a human.

**Signing pins while verification fetches, and the asymmetry is the decision, not an
oversight.** An issuer controls exactly which contexts it is willing to put its signature
under; that set should be small, reviewed and offline, so that the bytes a signature covers
are the bytes someone read. A verifier must accept credentials from issuers it has never met
and cannot enumerate their contexts in advance. `dcc-transaction-service` and
`verifier-core` are therefore correct to fetch, and must not be "aligned" with this service —
nor this one with them.

**Statics win outright.** `jsonld-document-loader` consults its static map before any
protocol handler (a fact `dcc-transaction-service` recorded the hard way, in
`verifier-document-loader.ts`). Pinning is therefore not a cache in front of a fetch — the two
options are not additive, and whatever is pinned is what gets signed over.

### Consequences

- **A vendored copy can drift from the published document**, and a credential signed under
  the pinned copy is canonized over the pinned bytes. This is the cost accepted. The drift
  test mitigates it but does not eliminate it: it skips when offline, so an environment with
  no egress will never notice a drift, and nothing re-runs it between builds.
- **Every new context is a code change and a deploy of this service.** That is the point — a
  new vocabulary under an issuer's signature should be reviewed — but it means a new profile
  in the monorepo cannot ship on its own.
- **`v1rc1` is a release candidate.** When `identification/v1` goes final it is a new URL,
  pinned beside this one, and a new profile version in the monorepo — not an edit to the
  vendored file.
- **Coverage is asserted by IRI, not by safe mode.** The VC 2.0 context declares an `@vocab`
  (`…/credentials/issuer-dependent#`), so under it an undefined term is silently mapped rather
  than dropped, and `jsonld`'s `safe: true` does not catch a misnamed field. The tests assert
  the IRIs the vendored context must supply and that nothing fell through to that fallback.

### Rejected alternatives

**`securityLoader({ fetchRemoteContexts: true })` in `src/issue.js`.** The one-line fix, and
it would have worked. Rejected for two reasons. First, availability and latency: the bundled
`httpClientHandler` sends `Cache-Control: no-cache` and `Pragma: no-cache` explicitly, so every
signature becomes two uncached round-trips — the `w3id.org` redirect, then GitHub Pages — and
issuance stops whenever GitHub Pages does. Second, integrity: the bytes a signature covers
would be whatever the network returned at that instant, from a host this service does not
control. Pinning is also simply how every other context in this loader already arrives.

**Publish an `identification-context` npm package and depend on it**, as
`@digitalcredentials/open-badges-context` does for Open Badges. The principled home, and it
would serve the verifiers too — but no such package exists
(`@digitalbazaar/identification-context`, `@digitalcredentials/identification-context` and
`identification-context` all 404 on the registry). Recorded as future work, upstream.

## Decision 2 — a context this service cannot serve is refused by name

**Before canonization, `IssuerInstance.issueCredential` looks up every string entry in the
credential's top-level `@context` in the loader, and throws a `SigningException(400)` naming
the first URL it cannot serve.** The loader's own error is kept as the exception's stack,
which `errorLogger` writes to the log, so the original text is not lost a second time.

- **After `injectContexts`.** The tenant's cryptosuite adds its own required contexts
  (`eddsa-rdfc-2022` adds data integrity); those must resolve too. A probe run before
  injection would pass and canonization would still fail.
- **In `issueCredential`, not the routes.** `POST /instance/:instanceId/credentials/sign` and
  the VCALM `POST /credentials/issue` both reach it through `issue()`, so one placement covers
  both and no route can grow a path around it. The OID4VP request-object route produces a JWS,
  does no JSON-LD work, and is untouched.
- **400, not 5xx and not 420.** Resending the same credential will fail the same way, so a
  status that tells a caller to retry would be wrong. 400 matches the service's other refusals
  of a credential's shape; `addIssuerId`'s 420 is not a registered status. The remedy may be
  ours rather than the caller's, and the message says what it is.
- **The message reaches the operator intact.** The monorepo's `aws-signing-service.ts` passes
  the response body through as `Failed to sign credential: HTTP <status> - <body>`, so the URL
  lands in the same log line the original incident was reported from.

### Consequences

- **One loader lookup per context on every signing request.** It is cheap *because* of
  decision 1 — every lookup is an in-memory map hit. Were fetching ever turned on, this probe
  would double the network cost of a signature, which is one more reason not to.
- **Only the top-level `@context` is probed.** Scoped contexts nested inside a pinned document
  are part of that document and reviewed with it; a credential that embeds a remote context
  URL inside a nested object would still fail with `jsonld`'s generic message. No profile does
  that today.
- **This is a diagnostic, not a policy.** It refuses nothing that canonization would have
  accepted; it only makes an existing failure name itself.

### Rejected alternatives

**Leave the message to `jsonld`.** Pinning one context fixes today's credential and leaves the
blindness for the next profile, which would arrive with the identical unreadable error and
cost the identical investigation.

**Catch `jsonld.InvalidUrl` after the fact and rewrite it from `error.details.url`.** Viable,
and free on the success path. Rejected because it depends on the internal shape of `jsonld`'s
error — `details` is not a documented contract — and on that error reaching this service
unwrapped through `@digitalbazaar/vc`, `jsonld-signatures` and whichever cryptosuite the tenant
uses, which differ in their `jsonld` versions today. The probe asks the loader directly, which
is the one component whose behaviour this service owns, and costs only in-memory lookups.
Logging `details` in `errorLogger` would be worth doing regardless.
