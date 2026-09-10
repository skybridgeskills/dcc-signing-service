#!/usr/bin/env node
import {
  generateEcdsaKeyMaterial,
  ECDSA_RDFC_2019
} from '../src/keyMaterial.js'
import { getSigningMaterial } from '../src/issue.js'

/**
 * Mint the key material for one `ecdsa-rdfc-2019` tenant.
 *
 * ## Why a CLI and not a fourth generator endpoint
 *
 * This service already exposes `GET /did-key-generator` and
 * `POST /did-web-generator`, so a third would have been the obvious move. It is
 * the wrong one twice over:
 *
 * - **The secret half would go over HTTP.** An Ed25519 seed handed out by those
 *   endpoints is a seed for a key the caller is about to own; here the response
 *   body would be a live P-256 private key, and the only place it belongs is a
 *   sensitive workspace variable.
 * - **This is run twice, ever** — once per environment, by hand, at
 *   provisioning time. An always-on endpoint for a twice-in-a-lifetime
 *   operation is a permanently reachable surface for no recurring benefit.
 *
 * ## Why minting is separate from signing at all
 *
 * `@digitalbazaar/ecdsa-multikey`'s `generate()` silently discards a `seed`
 * argument, so P-256 material cannot be re-derived — not here, not at boot, not
 * anywhere. It is minted once and persisted as **both** multibase halves,
 * because the WebCrypto import path cannot recover the public key from the
 * secret. See `docs/adr/2026-09-10-ecdsa-key-material-both-multibase-halves.md`.
 */

const HELP = `
Mint ECDSA (P-256) key material for one ecdsa-rdfc-2019 tenant.

  npm run mint:ecdsa
  npm run mint:ecdsa -- --tenant LER_TESTS_ECDSA

Options
  --tenant <NAME>   Also print the three values as TENANT_* environment lines,
                    ready to paste. Use the same uppercase suffix everywhere.
  -h, --help        Show this message.

Emits three values. WHERE EACH ONE GOES:

  publicKeyMultibase  -> TFC sensitive workspace variable, as
                         TENANT_KEY_PUBLIC_<TENANT>.
  secretKeyMultibase  -> TFC sensitive workspace variable, as
                         TENANT_KEY_SECRET_<TENANT>. Never into git, a ticket,
                         a chat message or a local file that outlives this run.
  did:key             -> git, in the infra PR: the tenant's issuer_did in the
                         plain tenants map. WITHOUT IT the tenant's OID4VCI
                         issuer metadata advertises the default suite while it
                         signs ecdsa-rdfc-2019.

Nothing durable in between. Close this terminal when the halves are in TFC.

Both halves belong to ONE tenant: TENANT_CRYPTOSUITE_<TENANT>=${ECDSA_RDFC_2019}
must be set alongside them, and TENANT_SEED_<TENANT> must NOT be — the service
refuses either mistake at startup.
`.trim()

const argv = process.argv.slice(2)

if (argv.includes('-h') || argv.includes('--help')) {
  console.log(HELP)
  process.exit(0)
}

const tenantFlag = argv.indexOf('--tenant')
const tenant = tenantFlag === -1 ? null : argv[tenantFlag + 1]
if (tenantFlag !== -1 && !tenant) {
  console.error('--tenant needs a tenant name. Run with --help.')
  process.exit(1)
}

const keyMaterial = await generateEcdsaKeyMaterial()

// The DID is derived through the same function that signs, rather than
// composed here. A second way of answering "what is this tenant's DID" is the
// drift `didWeb.js` exists to make impossible, and the value printed here is
// the one that goes into git — so it has to be the signing path's own answer.
const { didDocument } = await getSigningMaterial({
  method: 'key',
  keyMaterial,
  cryptosuite: ECDSA_RDFC_2019
})

console.log(`publicKeyMultibase  ${keyMaterial.publicKeyMultibase}`)
console.log(`secretKeyMultibase  ${keyMaterial.secretKeyMultibase}`)
console.log(`did:key             ${didDocument.id}`)

if (tenant) {
  console.log('')
  console.log(`TENANT_CRYPTOSUITE_${tenant}=${ECDSA_RDFC_2019}`)
  console.log(`TENANT_KEY_PUBLIC_${tenant}=${keyMaterial.publicKeyMultibase}`)
  console.log(`TENANT_KEY_SECRET_${tenant}=${keyMaterial.secretKeyMultibase}`)
}

console.log('')
console.log(
  'Both halves -> TFC sensitive workspace variables. The did:key -> git, in ' +
    'the infra PR. Nothing durable in between.'
)
