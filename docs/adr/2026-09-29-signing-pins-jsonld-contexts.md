# ADR: Signing pins the JSON-LD contexts it will sign under, carries the final VC 2.0 context, and refuses what it cannot sign by name

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
`@digitalcredentials/security-document-loader@6.0.x` defaults `fetchRemoteContexts` to
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
- **Coverage is asserted by IRI as well as by safe mode.** Safe mode catches a misnamed field
  only because the VC 2.0 context has no `@vocab` — which was not true of the copy this
  loader bundled before decision 3. The tests assert the IRIs the vendored context must
  supply and that nothing fell through to an `issuer-dependent#` fallback, so they stay honest
  either way.

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

## Decision 3 — the loader carries the final VC 2.0 context, and an undefined property is refused by name

**`@digitalcredentials/security-document-loader` moves from 6.0.x to 8.0.0**, and with it the
bundled `https://www.w3.org/ns/credentials/v2` moves from
`@digitalcredentials/credentials-v2-context@0.0.1-beta.0` to `1.0.0`.

The 6.0.x copy was a **pre-Recommendation draft**. It differed from the context the W3C
publishes in two ways. It declared `"@vocab": "https://www.w3.org/ns/credentials/issuer-dependent#"`,
which the final Recommendation removed (a catch-all `@vocab` now lives only in the examples
context). And it defined `statusSize`, `statusMessage` and `statusReference` on
`BitstringStatusList` rather than on `BitstringStatusListEntry`. `1.0.0` is deep-equal to the
published document; so, in 8.0.0, is every other bundled context served as JSON — seventeen
compared against their live URLs on 2026-09-29 — except one (below).

**The `@vocab` was not cosmetic.** Under it, a property no context defined was signed as an
`issuer-dependent#` term. A verifier that loads the published context drops that property
instead, canonizes different bytes, and fails the signature. Signing under the draft meant
signing credentials that only verifiers holding the same draft could verify.

**What the upgrade changes, measured rather than assumed.** Every golden fixture in
`skybridgeskills-monorepo` for the identity-document and Open Badge profiles canonizes to
byte-identical n-quads under 6.0.0 and 8.0.0, with no `issuer-dependent#` term, and signs under
both Ed25519Signature2020 and eddsa-rdfc-2022. None of the terms whose definitions moved is
emitted by any profile. What does change is a credential carrying a property **no context
defines**: under the draft it signed, and under the final context safe mode refuses it —
correctly, since a dropped property is in the JSON but not under the signature. Only
tenant-authored bodies can carry one: `custom_credential_v1` and the Open Badge
`json_template` mode.

**That refusal names the property.** `jsonld` reports it only as "Safe mode validation
error.", which reached callers as a 500. `IssuerInstance.issueCredential` now maps a
`jsonld.ValidationError` to a `SigningException(400)` naming
`details.event.details.property`, with the original error as the stack. The author's remedy
is a context that defines the term, or an inline `{ "@vocab": … }`, which the tests prove
signs. (Doing this required `await`ing `signVC`: the existing `try`/`catch` around a bare
`return` had never caught an async rejection.)

### Consequences

- **A tenant template with an undefined property that signs today will not sign after this
  deploys.** That is the intended behaviour of the final context and the reason for the named
  400, but it is a behaviour change for tenants, not only a dependency bump.
- **This reads `jsonld`'s error `details`, which decision 2 declined to rely on.** Here there is
  no loader-side equivalent to ask — finding the dropped property first would mean
  re-implementing expansion. The tests exercise both `jsonld` majors in the tree (8.3 via
  Ed25519Signature2020, 9.0 via eddsa-rdfc-2022), and a safe-mode error of an unfamiliar shape
  degrades to a generic 400 that still names `jsonld`'s event code, not to a crash.
- **The bundled Open Badges `context-3.0.3.json` still lags the published one** by two
  top-level terms, `endorsementJwt` and `jti`, which IMS added in place in 2026. No
  `@digitalcredentials/open-badges-context` release carries them, and no profile emits them,
  so this is recorded rather than fixed. A badge using either is refused, by name.
- **The verifiers are split, and this makes the split harmless for new credentials.**
  Verifiers consult bundled statics before fetching. Upstream `verifier-core` is already on
  loader 8.0.0; `dcc-transaction-service` verifies with 6.0.1, so under the draft. The two
  disagree only about a credential carrying an undefined property — and this service no
  longer signs one. A credential already issued with an `issuer-dependent#` term keeps
  verifying at `dcc-transaction-service` and fails at `verifier-core` and at any verifier
  holding the published context, as it already did. Moving `dcc-transaction-service` to 8.x is
  worth doing and is not done here.
- **`https://www.w3.org/ns/credentials/examples/v2` is not pinned.** The monorepo's own
  custom-credential fixtures list it, so such credentials fail today on both loader versions,
  by name. The W3C intends that context for examples; whether production credentials may use
  it is a product decision, not this one.

### Rejected alternatives

**Stay on 6.x and fix only the documentation.** Keeps every signature byte-identical, and keeps
signing undefined properties as terms that no verifier holding the published context can
check.

**Pin the final VC 2.0 context in `src/contexts/` over the bundled draft.** Statics are
last-write-wins, so it would work, but it shadows a bundled context with a local one and
leaves the rest of the 6.x set — including the older Open Badges copies — behind. The loader
release that already carries the final context is the smaller and more honest change.

