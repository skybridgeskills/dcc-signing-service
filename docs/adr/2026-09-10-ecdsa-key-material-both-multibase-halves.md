# ADR: ECDSA key material is persisted as both multibase halves, minted by a CLI, twice ever

**Date:** 2026-09-10
**Status:** Accepted
**Related work:** `feat/ecdsa-rdfc-2019`; the DCC services rollout M2; the `ecdsa-rdfc-2019`
identity defect; `@skybridgeskills/vc-signer`'s `KeyMaterial` union in `vcalm-status-service`.

## Context

Every tenant in this service was configured with one thing: a multibase seed in
`TENANT_SEED_<TENANT>`. The seed is deterministic input to Ed25519 key generation, so a
tenant's issuer DID is a pure function of its seed, and the same seed in staging and in
production gives the same DID. That property is load-bearing — the published `did:web`
document is derived from the seed on every request precisely so it cannot drift from the
signing key — and it made "the same tenant is identical in both environments" true by
construction.

`ecdsa-rdfc-2019` broke it silently.

`src/issue.js` called `EcdsaMultikey.generate({ curve: 'P-256', seed })`. But
`@digitalbazaar/ecdsa-multikey@1.8.0` destructures only
`{id, controller, curve, keyAgreement}` (`lib/index.js:23-25`): **the seed is not a
parameter**, so it was discarded without a word and `webcrypto.subtle.generateKey` ran
non-deterministically. Confirmed by reading the library and by control run — two
`generate()` calls with identical 32-byte seeds produce different public keys. Keys are
cached per process, so the DID was stable inside one container and changed on every
restart, redeploy and additional replica.

What that does *not* break is verification: `did:key` is self-certifying, so credentials
issued under a since-rotated DID still verify. What it breaks is issuer identity
continuity. The DID could not go on a trusted-issuer list, could not be declared in
`TENANT_ISSUER_<n>_ID_<T>`, and could not be asserted as the same issuer across a deploy.
The tenant's seed was decorative.

**The obvious fix does not exist.** There is no deterministic P-256 seed derivation
anywhere in this stack. The library's only raw-import path, `fromRaw`
(`lib/index.js:122-138`), requires `publicKey` as a **mandatory `Uint8Array`** and throws
without it — it cannot recompute the P-256 point from a secret alone. So the choice is not
*how to derive the key*; it is *where the key comes from at all*.

We have answered this once already, in-house. `@skybridgeskills/vc-signer`'s type surface
(`vcalm-status-service/packages/vc-signer/src/types.ts`) records it:

> ECDSA has no deterministic seed derivation in the stack we build on, so P-256 material is
> generated once and persisted at provisioning time — and both halves are persisted,
> because the WebCrypto import path cannot recover a P-256 public key from the secret
> multikey alone.

## Decision

**An `ecdsa-rdfc-2019` tenant is configured with persisted key material, not a seed.** It
declares `TENANT_KEY_PUBLIC_<T>` and `TENANT_KEY_SECRET_<T>` — both multibase halves — and
**no** `TENANT_SEED_<T>`. Key material is a two-variant discriminated union mirroring
`vc-signer`'s `KeyMaterial` (`src/keyMaterial.js`): `ed25519-seed` for every existing
tenant, `multikey` for ECDSA ones.

**Both halves, not just the secret.** `EcdsaMultikey.from` needs the public half; it cannot
be recovered from the secret. Persisting one is persisting an unusable key.

**Minted by a CLI, out of band.** `scripts/mint-ecdsa-key-material.js` (`npm run
mint:ecdsa`) emits `publicKeyMultibase`, `secretKeyMultibase` and the derived `did:key`.
Not a fourth `did-*-generator` HTTP endpoint — the response body would be a live P-256
private key — and not a magic `'generate'` value read at boot, because minting at boot *is*
the defect. It is run twice, ever: once for staging, once for production. The `did:key` it
prints is a requirement rather than a convenience: it becomes the tenant's `issuer_did` in
the plain `tenants` map, and without it the tenant's OID4VCI issuer metadata advertises the
default suite while it signs `ecdsa-rdfc-2019`.

**Both halves go to TFC sensitive workspace variables; the `did:key` goes into git, in the
infra PR. Nothing durable in between.**

**Every ambiguous or incomplete declaration is refused at startup**, naming the tenant:
`ecdsa-rdfc-2019` with only a seed; a tenant declaring both a seed and key material; half a
key pair in either direction; key material on a tenant that is not `ecdsa-rdfc-2019`. There
is deliberately no fallback for any of them — this defect existed *because* a discarded
seed failed silently, and the concerns register documents the identical disease one branch
over, where an unset `TENANT_CRYPTOSUITE_<T>` quietly downgrades a tenant to a
non-Data-Integrity proof.

**Tenant discovery is the union of the key-material families**, not `TENANT_SEED_` alone.
This is not a detail: discovery filtered on `TENANT_SEED_` and interpolated the sliced
suffix into the companion families, so a tenant carrying only key material was *invisible*
rather than merely unsigned — a 404 at issuance with nothing to explain it. Discovery also
matches `TENANT_KEY_SECRET_`, so a secret-only declaration reaches the half-a-pair refusal
instead of vanishing.

## Consequences

**We deliberately break "identical in both environments."** Staging and production ECDSA
tenants now have different issuer DIDs, because their key material is minted separately and
cannot be derived from a shared seed. That was already true in practice — the DID changed
on every restart — but it was not true *by design* until now, and anything that assumed one
DID per tenant across environments has to name the environment. Ed25519 tenants are
unchanged: same seed, same DID, both environments.

**An ECDSA tenant needs two SSM SecureString parameters, not one seed**, so the generated
`tenants` map is no longer uniform across suites. Terraform must emit `TENANT_CRYPTOSUITE_*`
and the key-material pair **together**; emitting the cryptosuite alone triggers the refusal
above — correct behaviour, broken deploy. Terraform validates the seed/key XOR at plan time
as well; that is belt-and-braces, not a substitute.

**The key material cannot be regenerated.** Losing the secret half means a new DID for that
tenant, and the old identity is gone. That is inherent to a key with no derivation path, not
a property of this decision.

**`src/keyMaterial.js` is a transitional local mirror, not a fourth cryptosuite policy.**
Recorded owner intent is that this service is converted to TypeScript and adopts
`@skybridgeskills/vc-signer`; that upgrade is deliberately deferred to keep this change
small. The discriminant and field names are copied verbatim so the eventual swap is a
**deletion, not a redesign**. `vc-signer` is unpublished (a workspace package, `404` on
npm) and this service is a live fork of `digitalcredentials/signing-service` in plain
JavaScript, so importing it today is a divergence paid on every future upstream merge.

**Already-issued ECDSA credentials keep verifying.** `did:key` is self-certifying. This
changes the affected tenants' DIDs one final time; they were minted under random keys that
were never assertable anyway.

**Local configuration was re-provisioned in the same commit.** `.env`'s `CCPD1ECDSA` tenant
carried a seed and would now be refused. New variables written ahead of the code that reads
them would sit inert, so the two land together.

## Rejected alternatives

**Derive the P-256 key from the seed, mirroring the Ed25519 arm.** This was the assumed fix
and it is impossible: `generate()` takes no seed and `fromRaw()` cannot reconstruct a public
key from a secret. Not a preference — a dead end.

**Exclude `ecdsa-rdfc-2019` from the deployed tenant matrix.** Free, and it removes the
cryptosuite the branch exists to ship. LER Tests wants the suite.

**A fourth PR, after the merge train.** It leaves the validated branch untouched, but the
first staging deploy would then carry a suite whose issuer identity rotates on restart —
while the decision is to *use* that suite. This lands as a commit on `feat/ecdsa-rdfc-2019`
before it merges instead.

**CI mints the key and writes it to SSM.** Rejected on volume, not on design. One row, in
two environments, minted twice in the lifetime of the system, does not justify giving a CI
job write access to signing-key parameters and a code path that can overwrite an issuer
identity. Two people running one command each is cheaper and has no standing blast radius.

> ⚠️ **Recorded flip condition.** *If ECDSA tenants stop being a single row, or if key
> rotation becomes routine, the CI-writes-SSM variant becomes the right answer.* It is the
> volume that makes it wrong today, not the design. A hand-run CLI does not scale to a
> tenant per customer or to a rotation schedule, and at that point the standing blast radius
> is the cheaper cost. Revisit this ADR when either condition is met rather than adding a
> second minting path beside it.

## Not decided here

**The `/health/ready` configured-vs-derived `did:key` assert.** The defect was silent partly
because readiness cross-checks configured against derived DIDs only for path-form `did:web`
instances, and a `did:key` assert would have caught it on the first deploy. It now has
something true to assert against — but it is deferred by owner decision, and this service
grows no identity endpoint for it here.
