# ADR: Normalise the published `did:web` document, and type it for the tenant's cryptosuite

**Date:** 2026-08-11
**Status:** Accepted
**Related work:** `GET /instance/:instanceId/did.json` (the publication endpoint), gap H1
(hand-maintained DID document disagreed with the configured seed), the CA Career Passport
wallet-interop probe runbook.

## Context

`GET /instance/:instanceId/did.json` derives a `did:web` tenant's DID document on every request
from that tenant's seed and `TENANT_DID_URL_{TENANT_NAME}`, through the same
`didWebDriver.generate({ seed, url })` call the signing path makes. Deriving rather than storing
is the whole point of the endpoint: gap H1 happened because a hand-copied `did.json` drifted from
the configured seed and nothing ever compared the two.

The driver is `@interop/did-web-resolver@5.0.0`, and for a *seeded* generate it returns:

```json
{
  "@context": ["…/did/v1", "…/suites/ed25519-2020/v1", "…/suites/x25519-2020/v1"],
  "id": "did:web:…",
  "assertionMethod": [{ "id": "did:web:…#z6Mk…", "type": "Ed25519VerificationKey2020", … }]
}
```

Two library behaviours combine to produce that. Passing a `seed` collapses the driver's
five-purpose default key map to `{ assertionMethod: keyPair }` (`DidWebResolver.js:195`), and
`initKeys` always embeds the exported method into the relationship array and never populates a
top-level `verificationMethod` (`:133`). Deterministic seed-based generation — exactly what this
service does — takes that path. `@digitalbazaar/did-method-key`, which produces our `did:key`
documents, has neither behaviour.

Three problems follow.

1. **The embedded form is legal but a poor bet.** DID Core 1.0 §5.3.1 permits a verification
   relationship's value to be either a DID URL or an embedded verification method map, so this is
   an interop-robustness defect and not a spec violation. A wallet that rejects it is not wrong.
   This service exists to test third-party wallets and make their failures attributable to them;
   shipping a document a vendor may legitimately refuse defeats that.
2. **The `x25519` context is declared but never used** — no `keyAgreement` key is derived. Benign
   for verification, but it reads as a defect to anyone scoring the document.
3. **The document does not say which suite signs.** The service issues `did:web` under both
   `Ed25519Signature2020` and `eddsa-rdfc-2022`, from one key at one `#fragment`. A
   `DataIntegrityProof` verifier resolves the method through `Ed25519Multikey.from`, which
   expects `type: "Multikey"`. Our own verifier translates an `Ed25519VerificationKey2020` method
   for us; a third-party wallet is under no obligation to.

The evidence that this matters is already in the tree of a sibling effort: the Certree campaign
carries **two** hand-maintained copies of one tenant's document, differing only in verification
method type and context. Someone hit problem 3 and forked the document rather than fixing the
generator — and that fork is where gap H1 came from.

A tempting counter-argument must be recorded as invalid: *"we already issue `eddsa-rdfc-2022`
over `did:key`, whose document also says `Ed25519VerificationKey2020`, and wallets accept it."* A
`did:key` document is composed **by the consumer** from the identifier — the wallet never sees
ours. `did:web` is the first and only case where our document shape reaches a vendor's resolver,
so no `did:key` sitting is evidence about it.

## Decision

Two decisions, taken together.

### 1. Normalise the driver's output downstream, rather than switching or forking the driver

`src/didWeb.js` gains `normaliseDidDocument(didDocument, suiteModule)`, applied inside
`getTenantDidDocument` (so the endpoint has no path around it) and in `generate.js` for
`POST /did-web-generator` (so the service has one answer to "what does our did:web document look
like"). It produces:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "<suite context>"],
  "id": "did:web:…",
  "verificationMethod": [{ "id": "did:web:…#z6Mk…", "type": "<suite type>",
                           "controller": "did:web:…", "publicKeyMultibase": "z6Mk…" }],
  "assertionMethod": ["did:web:…#z6Mk…"],
  "authentication":  ["did:web:…#z6Mk…"]
}
```

The unused `x25519` context is dropped rather than backed with a `keyAgreement` key we have no
use for. `capabilityInvocation` and `capabilityDelegation` are omitted: an issuer has no use for
them.

Three constraints make this safe rather than a return to composing documents by hand:

- It **moves** the method the driver already produced. It never constructs a verification method
  from separately-held key material. A document composed beside the signing path is precisely the
  drift the endpoint exists to make impossible, and the repo's anti-drift test still compares the
  published method against what `getSigningMaterial` derives for the same seed and URL.
- Every value except `type` is carried through verbatim — in particular `id`, which contains the
  `#fragment` that an issued credential's `proof.verificationMethod` points at.
- If the driver's output is not the shape the normaliser knows how to re-express, it **throws a
  500**. A silent fallback would publish a key-less document that still looks like a DID document
  — the same class of failure, reached by a different route.

### 2. The verification method's `type` follows the tenant's configured cryptosuite

| `TENANT_CRYPTOSUITE_{TENANT_NAME}` | VM `type` | Second `@context` entry |
| --- | --- | --- |
| *(unset)* / `Ed25519Signature2020` | `Ed25519VerificationKey2020` | `…/suites/ed25519-2020/v1` |
| `eddsa-rdfc-2022` | `Multikey` | `https://w3id.org/security/multikey/v1` |
| `ecdsa-rdfc-2019` | — | refused, unchanged |

That knowledge lives in the three `src/suites/*Suite.js` modules as `getVerificationMethodType()`
and `getDidDocumentContext()`, beside the existing `getProofType()` — the same kind of fact, in
the same place. They are deliberately **not** folded into `getRequiredContexts()`, which returns
*credential* contexts (`credentials/v2`, `data-integrity/v2`) and has nothing to do with a DID
document; a test asserts the two do not overlap.

`selectSuite` moved out of `issue.js` into `src/suites/selectSuite.js`, unchanged. `issue.js`
already imports `didWeb.js`, so having `didWeb.js` import `selectSuite` back from `issue.js`
would have created a cycle. Both now import downwards.

`ecdsa-rdfc-2019` + `did:web` stays refused, before a suite is selected. Normalisation does not
open that door: for such a tenant the driver still produces an Ed25519 key, so restyling the
document would publish a key the tenant never signs with.

## Rejected alternatives

**Switching to, or forking, `@interop/did-web-resolver`.** The better long-term answer — both
behaviours are upstream defects and are recorded as future work — but a driver swap on the
campaign's timeline risks changing the derived key or identifier, and forking adds a dependency
we would have to carry. Normalising downstream is reversible and touches one function.

**Option A — always emit `Ed25519VerificationKey2020` and rely on verifier translation.** Keeps
the document a pure function of the key. Rejected because a strict `Multikey`-only wallet would
fail on an `eddsa-rdfc-2022` credential, and the harness would score that against the vendor when
the cause is our document. That is the exact failure mode this service is built to avoid.

**Option B — two verification methods at distinct fragments, one per type.** Rejected because
signing would have to pick a fragment per suite, which changes `proof.verificationMethod` on
newly issued credentials. Certree's sitting is already issued and already scored; changing the
fragment would break comparability with a result on the record.

**Deriving an X25519 `keyAgreement` key to justify the declared context.** Rejected: this
service issues credentials and has no use for key agreement. Dropping the context is honest;
minting an unused key is not.

## Consequences

- **`proof.verificationMethod` on issued credentials is unchanged.** The fragment is the key's
  multibase value and does not depend on the verification method type. This is asserted in
  `app.test.js`: the same tenant's published document and a credential it signs in the same test
  must name the same method, and the two tenant configurations over one seed must agree on the
  fragment.
- **The published document is now a function of the key *and* of tenant configuration**, not of
  the key alone. This is the accepted cost of decision 2, and it is recorded here rather than
  discovered later. It does not weaken the anti-drift property: the same setting selects the
  signing suite, so the document describes the key the way the signer will reference it.
- **Our documents no longer match what `@interop/did-web-resolver` emits.** A version bump could
  silently change the input the normaliser expects — which is why it throws on an unexpected
  shape instead of coping, and why a driver upgrade must be treated as a shape change.
- Anything asserting on the published document reads `verificationMethod[0]`, not
  `assertionMethod[0]`. `dcc-transaction-service` proxies the document as-is and inherits the new
  shape with no change on that side.
- The two hand-maintained documents in the Certree campaign tree now have no reason to exist and
  should be deleted once this endpoint is confirmed serving.
