# ADR: Sign OID4VP request objects here, with the tenant's existing key

**Date:** 2026-08-25
**Status:** Accepted
**Related work:** `POST /instance/:instanceId/openid4vp/request-object/sign`,
`GET /instance/:instanceId/did.json` (the publication endpoint), `didWeb.js`'s single-driver
invariant, gap H1, and the CA Career Passport three-wallet evaluation.

## Context

This service has signed exactly one kind of thing: verifiable credentials. The verifier
(`dcc-transaction-service`) now needs a second kind — an **OID4VP authorization request object**,
signed as a compact JWS — to serve a conformant request under the `decentralized_identifier`
Client Identifier Prefix.

⚠️ **That prefix is the whole reason this lands here rather than there.** OID4VP §5.9.3 identifies
the verifier by a DID, and the wallet resolves that DID's document to find the key. The JOSE `kid`
in the signed request must therefore name a key in that document's `verificationMethod`.

Two components could hold the signing key:

- **The verifier**, with a local key behind its own `did:web`. No round trip per request.
- **This service**, reusing the tenant's existing seed.

## Decision

**Sign it here, with the tenant's existing seed, and derive the `kid` from the published document.**

### 1. Because this is the only place both come from one seed

`didWeb.js` exists for precisely this invariant, and says so — *"this module exists precisely so a
published DID document cannot disagree with the key that signs. A single instance removes the only
way that could happen inside this process."*

⚠️ A key in the verifier would reintroduce the two-drivers drift **across a service boundary**: a
distributed gap H1, where a hand-maintained document said one thing while the configured seed
produced another and nothing ever compared them — a failure that survived an entire milestone
unnoticed. This endpoint is that existing invariant extended to a second signature type, not a new
responsibility.

The rejected alternative stays available if the round trip ever becomes the wrong shape.
**Performance is accepted knowingly:** one JWS per `request_uri` GET, at most one per exchange, and
the by-value delivery never fetches at all.

### 2. The `kid` is READ from the published document, never composed

⚠️ `signRequestObject` calls `getTenantDidDocument` — the very function the `did.json` endpoint
serves from — and takes `verificationMethod[0].id`. It never builds `did + '#' + something`.

A composed `kid` is a second statement about which key signs, and a second statement is what
`didWeb.js` was written to make impossible. **The test asserts the `kid` against the live
`did.json` response rather than a constant**, because a constant would keep passing while the two
drifted apart — which is the exact failure being prevented.

It also buys every refusal for free, with identical wording: unknown tenant, non-`did:web` tenant,
the ECDSA refusal, and a missing URL all throw from the one place that already decides them.

### 3. The algorithm is EdDSA, and that is forced

`ECDSA_DID_WEB_REFUSAL` records that the `did:web` driver cannot express a P-256 verification
method. A `did:web` tenant therefore signs Ed25519 and nothing else, and an ECDSA `did:web` tenant
is refused **with that same shared constant** — now its third call site, not a fourth wording.

⚠️ **This has an interop consequence, and it is deliberately not papered over.** ES256 is the
de-facto default for OID4VP request-object signing in the mDL/EUDI world. A conformant signed arm
may therefore prove **less** interoperable than the unsigned accommodation it is meant to replace.
That is a thing to measure. **No P-256 path was added here to pre-empt it** — that would be a new
key, a new document and a different decision.

### 4. Non-credential payloads are in scope; choosing them is not

The endpoint signs what it is handed. Which claims go into a request object is the verifier's
decision, and duplicating that judgement here would be a second place the wire is decided.

### 5. No unsigned fallback, ever

⚠️ Every failure is a named error. An unsigned result from a *sign* endpoint is the worst available
outcome, because it looks like success — and the verifier separately serves a genuinely unsigned
`alg: none` arm as a registered accommodation, so an accidental unsigned result here would be
indistinguishable from a deliberate one there.

**The test asserts the signature segment is NON-EMPTY** for exactly that reason. A test that only
counted three segments would pass for both.

## Consequences

- **This service now signs something that is not a credential.** Bounded by: credential issuance is
  untouched, no new key material, no new driver, and the payload is chosen elsewhere.
- ⚠️ **A `did:key` tenant cannot use this endpoint.** It publishes no document at a URL, so
  `getTenantDidDocument` refuses it — and the refusal is inherited rather than re-decided. A
  deployment whose tenants are all `did:key` cannot serve the conformant arm without a decision
  that does not exist yet.
- **The verifier gains a runtime dependency on this service for that arm.** Availability is now
  coupled where it was not; the by-value and unsigned arms are unaffected.
- ⚠️ **`kid` stability follows the seed.** Rotating a tenant's seed changes the published document
  and the `kid` together, which is correct — but any wallet that cached the old document sees a
  signature it cannot verify.

## Alternatives considered

- **A local key in the verifier, behind its own `did:web`.** Rejected: it puts the published
  document and the signing key in different processes with no comparison between them, which is
  gap H1 with a network in the middle. Recorded as the fallback if the round trip becomes the wrong
  shape.
- **Composing the `kid` from the DID plus a known fragment.** Rejected — see decision 2. It is
  cheaper and it is the failure mode.
- **Adding an ES256 path so the signed arm matches the mDL/EUDI default.** Rejected as out of
  scope: new key material and a new document shape, taken before any evidence that the EdDSA arm
  fails. Measure first.
- **Falling back to an unsigned request object when signing is unavailable.** Rejected outright.
  It converts an outage into a silent conformance downgrade.
