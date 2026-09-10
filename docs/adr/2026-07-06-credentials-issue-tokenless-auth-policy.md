# ADR: Authentication policy for `/credentials/issue` (tokenless tenants stay open)

**Date:** 2026-07-06
**Status:** Accepted
**Related finding:** 04 (fail-open auth for tokenless tenants) — review
`2026-07-06-feature-data-integrity-cryptosuites`

## Context

The VCALM `POST /credentials/issue` endpoint identifies the tenant from the
`Authorization` header and is documented as requiring authentication. As
implemented, a tenant without a `TENANT_AUTH_TOKEN_{TENANT_NAME}` configured is
authenticated by Basic Auth with **any** password: presence of the header is
required, but a correct secret is not. The three default tenants (`test`,
`testing`, `random`) ship without tokens and are therefore reachable this way.

This is a durable security-posture decision: it defines what "authenticated
issuance" guarantees for this service, and it affects every tenant onboarding.

Two options were considered:

- **Option A — require a token on the issue path.** Tenants without
  `TENANT_AUTH_TOKEN` are rejected on `/credentials/issue`. Fail-closed; the
  presence of the endpoint implies a real secret is required. Safer by default
  and matches the endpoint's stated purpose, but requires setting tokens for the
  default/dev tenants and any existing tokenless tenants before they can use the
  issue path, breaking frictionless local/dev use.
- **Option B — tokenless is an explicit open mode.** Keep the current behavior,
  but treat a tokenless tenant as a deliberate "no-secret" mode: document it as
  such and emit a startup warning for any tenant reachable without a token.

## Decision

Adopt **Option B**. `/credentials/issue` stays **open** for tokenless tenants
(any password accepted once the tenant name matches). We do **not** fail-closed.
Instead we make the open surface explicit:

- A consolidated `[auth]` warning is logged on config load/refresh listing every
  tenant that has no `TENANT_AUTH_TOKEN` and is therefore open.
- The README documents that a tenant without a token is open on
  `/credentials/issue`, that this is an intentional mode, and that setting a
  token is what makes a tenant require authentication.

This decision keeps the current developer ergonomics (default/dev tenants work
without extra configuration) while ensuring the fail-open surface is understood
by every operator rather than being silent.

Related hardening shipped alongside this decision (not a change to the tokenless
behavior itself): Basic-Auth passwords are split on the first colon only so
colon-containing passwords authenticate correctly; secret comparisons use
`crypto.timingSafeEqual`; and duplicate Bearer tokens across tenants log a
warning instead of silently overwriting the reverse lookup.

## Rejected alternative

**Option A (require a token / fail-closed).** Rejected for now because it would
break the default and dev tenants, which are relied on for local use and tests,
without a corresponding dev-override mechanism. It remains the safer long-term
posture and can be revisited (e.g. with an explicit env/dev override) if the
service's threat model changes.

## Consequences

- Operators **must** set `TENANT_AUTH_TOKEN_{TENANT_NAME}` to actually gate a
  tenant behind authentication; otherwise that tenant is open on
  `/credentials/issue`.
- The startup/config-load warning surfaces the open surface so it is not silent.
- The default tenants (`test`, `testing`, `random`) remain open by design; do not
  rely on them for anything requiring real authentication.
