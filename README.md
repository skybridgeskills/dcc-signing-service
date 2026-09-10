# Digital Credentials Consortium Verifiable Credentials Signing Service

[![Build status](https://img.shields.io/github/actions/workflow/status/digitalcredentials/signing-service/main.yml?branch=main)](https://github.com/digitalcredentials/signing-service/actions?query=workflow%3A%22Node.js+CI%22)

IMPORTANT NOTE ABOUT VERSIONING: If you are using a Docker Hub image of this repository, make sure you are reading the version of this README that corresponds to your Docker Hub version. If, for example, you are using the image `digitalcredentials/status-service:1.0.0` then you'll want to use the corresponding tagged repo: [https://github.com/digitalcredentials/status-service/tree/v1.0.0](https://github.com/digitalcredentials/status-service/tree/v0.1.0). If you are new here, then just read on...

## Table of Contents

- [Summary](#summary)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Tenants](#tenants)
  - [Signing Key](#signing-key)
    - [did:key generator](#didkey-generator)
    - [did:web generator](#didweb-generator)
    - [ecdsa-rdfc-2019 key material](#ecdsa-rdfc-2019-key-material)
  - [DID Registries](#did-registries)
  - [did:key](#didkey)
  - [did:web](#didweb)
    - [Configuring a did:web tenant](#configuring-a-didweb-tenant)
    - [Publishing the DID document](#publishing-the-did-document)
      - [The published shape](#the-published-shape)
    - [ecdsa-rdfc-2019 is did:key only](#ecdsa-rdfc-2019-is-didkey-only)
  - [Revocation](#revocation)
- [Usage](#usage)
  - [Sign a credential](#sign-a-credential)
  - [VCALM Issue Endpoint](#vcalm-issue-endpoint)
  - [Learner Credential Wallet](#learner-credential-wallet)
- [Versioning](#versioning)
- [Logging](#logging)
- [Health Check](#health-check)
- [Development](#development)
  - [Testing](#testing)
- [Contribute](#contribute)
- [License](#license)

## Summary

Use this express server to sign [Verifiable Credentials](https://www.w3.org/TR/vc-data-model/). NEW: as of version 1.0.0 the signing-service works with both version 1 and version 2 Verifiable Credentials.

Implements six http endpoints:

- POST /instance/:instanceId/credentials/sign

Which signs and returns a [Verifiable Credential](https://www.w3.org/TR/vc-data-model/) that has been posted to it. This is the legacy endpoint for backwards compatibility.

- POST /credentials/issue

Which is the VCALM-compatible endpoint for issuing credentials. The tenant is identified and authenticated via `Authorization` (Basic username = tenant name, or Bearer token from `TENANT_AUTH_TOKEN_{TENANT_NAME}`). See the [VCALM Issue Endpoint](#vcalm-issue-endpoint) section.

- GET /did-key-generator

Which is a convenience method for generating a new signing key, encoded as a [Decentralized Identifier (DID)](https://www.w3.org/TR/did-core/) and specifically using the [did:key method](https://w3c-ccg.github.io/did-method-key/). Read about how to use it in the [did:key generator section](#didkey-generator).

- POST /did-web-generator

Which is a convenience method for generating a new signing key, encoded as a [Decentralized Identifier (DID)](https://www.w3.org/TR/did-core/), specifically using the [did:web method](https://w3c-ccg.github.io/did-method-web/). Read about how to use it in the [did:web generator section](#didweb-generator).

- GET /instance/:instanceId/did.json

Which publishes a `did:web` tenant's DID document, **derived** on every request from that tenant's configured seed and `TENANT_DID_URL_{TENANT_NAME}` — so it cannot disagree with the key that signs. The key is published under `verificationMethod` and referenced by fragment from `assertionMethod` and `authentication`, with a type matching the tenant's cryptosuite. Unauthenticated, because a DID document is public by definition. Returns 404 for a `did:key` tenant, which has no document to host. Read more in the [Publishing the DID document](#publishing-the-did-document) section.

- GET /healthz

Which is an endpoint typically meant to be called by the Docker [HEALTHCHECK](https://docs.docker.com/reference/dockerfile/#healthcheck) option for a specific service. Read more below in the [Health Check](#health-check) section.

The signing endpoint is meant to be called as a RESTful service from any software wanting to sign a credential. It is used, for example, by the [DCC issuer-coordinator](https://github.com/digitalcredentials/issuer-coordinator) and the [DCC workflow-coordinator](https://github.com/digitalcredentials/worfklow-coordinator). See an [example docker-compose configuration](https://github.com/digitalcredentials/workflow-coordinator/blob/main/docker-compose.yml) from the workflow-coordinator repository for an example of how to run this service.

This service supports multiple signing keys ([DIDs](https://www.w3.org/TR/did-core/)). The legacy sign endpoint identifies the tenant with `:instanceId` in the URL. The VCALM issue endpoint identifies the tenant from the `Authorization` header instead (see [VCALM Issue Endpoint](#vcalm-issue-endpoint)). An `instance` is sometimes also called a `tenant`.

You may also want to take a look at the [DCC issuer-coordinator](https://github.com/digitalcredentials/issuer-coordinator), as it provides bearer token security over tenant endpoints, and combines both signing and status revocation as a single service. It also describes a model for composing DCC services within a Docker Compose network.

The [DCC workflow-coordinator](https://github.com/digitalcredentials/workflow-coordinator) goes a step further and adds support for directly adding credentials to a wallet like the [Learner Credential Wallet](lcw.app).

Or if you are ready to dive right in and issue a whole batch of credentials, with csv upload, email notification for recipients, and wallet collection then check out the [DCC Admin Dashboard](https://github.com/digitalcredentials/admin-dashboard).

## Quick Start

You can try this signing-service in about three minutes:

1. Install Docker, which is made very easy with the [Docker installers for Windows, Mac, and Linux](https://docs.docker.com/engine/install/).

2. From a terminal prompt, run:

```
docker run -dp 4006:4006 digitalcredentials/signing-service:1.0.0
```

You can now issue test credentials as explained in the [Sign a Credential](#sign-a-credential) section.

IMPORTANT: this quick start version uses a test signing key that is not registered to an actual issuer, so when verifying credentials issued with the test key they will be marked as test credentials. To use this in production you'll have to generate your own signing key, and register it publicly. To do so, read on...

## Configuration

### Environment Variables

There is a sample .env file provided called .env.example to help you get started with your own .env file. The supported fields:

| Key                                | Description                                                                                                         | Default                    | Required |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------- | -------------------------- | -------- |
| `PORT`                             | http port on which to run the express app                                                                           | 4006                       | no       |
| `ENABLE_HTTPS_FOR_DEV`             | runs the dev server over https - ONLY FOR DEV - typically to allow CORS calls from a browser                        | false                      | no       |
| `TENANT_SEED_{TENANT_NAME}`        | see [tenants](#tenants) section for instructions. Ed25519 suites only — an `ecdsa-rdfc-2019` tenant must NOT set one | no                         | no       |
| `TENANT_KEY_PUBLIC_{TENANT_NAME}`  | public multibase half of an `ecdsa-rdfc-2019` tenant's P-256 key — see [ecdsa-rdfc-2019 key material](#ecdsa-rdfc-2019-key-material) |                            | no       |
| `TENANT_KEY_SECRET_{TENANT_NAME}`  | secret multibase half of the same key. Both halves or neither                                                       |                            | no       |
| `TENANT_DIDMETHOD_{TENANT_NAME}`   | did method (`key` or `web`) to use for signing on this tenant                                                       | `key`                      | no       |
| `TENANT_DID_URL_{TENANT_NAME}`     | url to use for did:web                                                                                              |                            | no       |
| `TENANT_CRYPTOSUITE_{TENANT_NAME}` | cryptosuite to use (`eddsa-rdfc-2022` or `ecdsa-rdfc-2019` for DataIntegrityProof, omit for Ed25519Signature2020)    | `Ed25519Signature2020`     | no       |
| `TENANT_AUTH_TOKEN_{TENANT_NAME}`  | Secret for Bearer (`Authorization: Bearer …`) or Basic Auth password on `/credentials/issue`. Each token must be unique if you use Bearer. See [VCALM endpoint](#vcalm-issue-endpoint) |                            | no       |
| `ENABLE_ACCESS_LOGGING`            | log all http calls to the service - see [Logging](#logging)                                                         | true                       | no       |
| `ERROR_LOG_FILE`                   | log file for all errors - see [Logging](#logging)                                                                   | no                         | no       |
| `LOG_ALL_FILE`                     | log file for everything - see [Logging](#logging)                                                                   | no                         | no       |
| `CONSOLE_LOG_LEVEL`                | console log level - see [Logging](#logging)                                                                         | silly                      | no       |
| `LOG_LEVEL`                        | log level for application - see [Logging](#logging)                                                                 | silly                      | no       |
| `HEALTH_CHECK_SMTP_HOST`           | SMTP host for unhealthy notification emails - see [Health Check](#health-check)                                     | no                         | no       |
| `HEALTH_CHECK_SMTP_USER`           | SMTP user for unhealthy notification emails - see [Health Check](#health-check)                                     | no                         | no       |
| `HEALTH_CHECK_SMTP_PASS`           | SMTP password for unhealthy notification emails - see [Health Check](#health-check)                                 | no                         | no       |
| `HEALTH_CHECK_EMAIL_FROM`          | name of email sender for unhealthy notifications emails - see [Health Check](#health-check)                         | no                         | no       |
| `HEALTH_CHECK_EMAIL_RECIPIENT`     | recipient when unhealthy - see [Health Check](#health-check)                                                        | no                         | no       |
| `HEALTH_CHECK_EMAIL_SUBJECT`       | email subject when unhealthy - see [Health Check](#health-check)                                                    | no                         | no       |
| `HEALTH_CHECK_WEB_HOOK`            | posted to when unhealthy - see [Health Check](#health-check)                                                        | no                         | no       |
| `HEALTH_CHECK_SERVICE_URL`         | local url for this service - see [Health Check](#health-check)                                                      | http://SIGNER:4006/healthz | no       |
| `HEALTH_CHECK_SERVICE_NAME`        | service name to use in error messages - see [Health Check](#health-check)                                           | SIGNING-SERVICE            | no       |

### Tenants

You might want to allow more than one signing key ([DID](https://www.w3.org/TR/did-core/)) to be used with the issuer. For example, you might want to sign university/college degree diplomas with a key ([DID](https://www.w3.org/TR/did-core/)) that is only used by the registrar, but then also allow certificates for individual courses to be signed by by different keys ([DIDs](https://www.w3.org/TR/did-core/)) that are owned by the faculty or department that teaches the course.

We're calling these different signing authorities 'tenants' (or 'instances'). You can set up as many tenants as you like by including a `TENANT_SEED_{TENANT_NAME}={seed}` environment variable for every 'tenant'. (NOTE: if you are using a did:web key, you must additinally specify `TENANT_DIDMETHOD_{TENANT_NAME}=web` and `TENANT_DID_URL_{TENANT_NAME}={the url for your did:web}`) for each did:web tenant. Read more in the [did:web generator section](#didweb-generator).

NOTE: the `seed` is explained below in the [Signing key section](#signing-key).

So, if you wanted to set up two tenants, one for degrees and one for completion of the Econ101 course then you could create the tenants by setting the following in the .env file:

```
TENANT_SEED_DEGREES=z1AoLPRWHSKasPH1unbY1A6ZFF2Pdzzp7D2CkpK6YYYdKTN
TENANT_SEED_ECON101=Z1genK82erz1AoLPRWHSKZFF2Pdzzp7D2CkpK6YYYdKTNat
```


**Use a fixed seed for any tenant whose identity must be stable.** Setting a
seed to `generate` mints a fresh key on every service start, so the tenant's
issuer DID silently changes across restarts. Credentials issued either side of
a restart then carry different issuers — harmless for verification, since
`did:key` is self-describing, but confusing for anything that correlates
credentials to an issuer over time (evaluation runs, status lists, audit
trails). Generate a seed once via `/did-key-generator` and pin it. (An
`ecdsa-rdfc-2019` tenant has no seed to pin — see
[ecdsa-rdfc-2019 key material](#ecdsa-rdfc-2019-key-material).)

**Supported cryptosuites** (`TENANT_CRYPTOSUITE_{TENANT_NAME}`):

| Value | Proof | DID methods |
| --- | --- | --- |
| *(unset)* | `Ed25519Signature2020` (legacy default) | `did:key`, `did:web` |
| `eddsa-rdfc-2022` | `DataIntegrityProof` | `did:key`, `did:web` |
| `ecdsa-rdfc-2019` | `DataIntegrityProof`, P-256 | **`did:key` only** — see below |

`ecdsa-rdfc-2019` is refused for `did:web`. The did:web driver composes a DID
document whose `@context` is hardcoded to the Ed25519/X25519 suite contexts and
emits no verification method for an ECDSA key, so publishing a P-256 key there
would misdescribe it to every relying party. Supporting it means composing the
DID document ourselves or replacing the resolver.

**An `ecdsa-rdfc-2019` tenant is configured differently from every other
tenant: it carries no seed.** P-256 key material cannot be derived from a seed
in this stack, so it is minted once and both multibase halves are persisted:

```
TENANT_CRYPTOSUITE_LEDGERLAB=ecdsa-rdfc-2019
TENANT_KEY_PUBLIC_LEDGERLAB=zDna…
TENANT_KEY_SECRET_LEDGERLAB=z42t…
```

See [ecdsa-rdfc-2019 key material](#ecdsa-rdfc-2019-key-material) for how to
mint them. **Four declarations are refused at startup**, naming the tenant,
rather than falling back to anything:

| Declaration | Why it is refused |
| --- | --- |
| `ecdsa-rdfc-2019` with only a `TENANT_SEED_` | The P-256 generator discards its seed, so the seed pins nothing and the tenant's DID would change on every restart |
| Both a `TENANT_SEED_` and key material | Nothing can decide which is authoritative |
| `TENANT_KEY_PUBLIC_` without `TENANT_KEY_SECRET_`, or the reverse | Half a key pair cannot sign, and the missing half cannot be derived from the one present |
| Key material on a tenant that is not `ecdsa-rdfc-2019` | No other suite consumes multibase halves |

For the legacy sign endpoint, tenant names appear in the URL:

```
http://myhost.org/instance/degrees/credentials/sign
http://myhost.org/instance/econ101/credentials/sign
```

The VCALM `/credentials/issue` path is the same for every tenant: `https://myhost.org/credentials/issue`. Identify the tenant with Basic Auth (`username` = tenant name, e.g. `degrees`) or with Bearer auth and `TENANT_AUTH_TOKEN_{TENANT_NAME}`. See the [VCALM Issue Endpoint](#vcalm-issue-endpoint) section.

Note that the legacy `/credentials/sign` endpoint is unsecured by default. `/credentials/issue` always requires an `Authorization` header.

#### Cryptosuite Configuration

By default, tenants use the `Ed25519Signature2020` proof type for signing credentials. You can configure a tenant to use the modern `eddsa-rdfc-2022` cryptosuite (which produces `DataIntegrityProof` proofs) by setting:

```
TENANT_CRYPTOSUITE_DEGREES=eddsa-rdfc-2022
```

When `eddsa-rdfc-2022` is specified, the service will use the Data Integrity specification with the eddsa-rdfc-2022 cryptosuite. If not specified (or set to any other value), the service defaults to `Ed25519Signature2020` for backwards compatibility.

#### Default Tenants

There are three tenants setup by default (for `/credentials/sign` paths use `instance/{name}/credentials/sign`; for `/credentials/issue` use Basic Auth with username `test`, `testing`, or `random`):

The `test` and `testing` tenants both use this seed and corresponding [DID](https://www.w3.org/TR/did-core/):

- seed - `z1AeiPT496wWmo9BG2QYXeTusgFSZPNG3T9wNeTtjrQ3rCB`
- did - `did:key:z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q`

That [DID](https://www.w3.org/TR/did-core/) for the `test` and `testing` tenants is currently registered in the [DCC Sandbox Registry](https://github.com/digitalcredentials/sandbox-registry) so that any credentials generated with that tenant will, when verified, show as having originated from the DCC test issuer.

There is no effectively difference between the `test` and `testing` tenants - both are included simply for ease of use.

See the [Sign a credential](#sign-a-credential) section for a working CURL example of how to sign with the `test` tenant.

The `random` tenant generates a random signing key every time the server is started. This is strictly meant for testing and experimenting. For production use, you must generate your own signing keys.

Read on to generate your signing keys...

### Signing key

The issuer is by default configured with a signing key that can only be used for testing and evaluation.

To issue your own credentials you must generate your own signing key and keep it private. We've tried to make that a little easier by providing two convenience endpoints in the issuer that you can use to generate a brand new key. One generates a new [did:key](https://w3c-ccg.github.io/did-method-key/) and the other a new [did:web](https://w3c-ccg.github.io/did-method-web/).

#### did:key generator

You can generate a new did:key by hitting the convenience endpoint with the following CURL command:

`curl --location 'http://localhost:4006/did-key-generator'`

This will return a json document with:

- a seed
- the corresponding [DID](https://www.w3.org/TR/did-core/)
- the corresponding [DID](https://www.w3.org/TR/did-core/) Document

The returned result will look something like this:

<details> 
<summary>Show code</summary>
  
```
{
	"seed": "z1AjQUBZCNoiyPUC8zbbF29gLdZtHRqT6yPdFGtqJa5VfQ6",
	"did": "did:key:z6MkweTn1XVAiFfHjiH48oLknjNqRs43ayzguc8G8VbEAVm4",
	"didDocument": {
		"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1", "https://w3id.org/security/suites/x25519-2020/v1"],
		"id": "did:key:z6MkweTn1XVAiFfHjiH48oLknjNqRs43ayzguc8G8VbEAVm4",
		"verificationMethod": [{
			"id": "did:key:z6MkweTn1XVAiFfHjiH48oLknjNqRs43ayzguc8G8VbEAVm4#z6MkweTn1XVAiFfHjiH48oLknjNqRs43ayzguc8G8VbEAVm4",
			"type": "Ed25519VerificationKey2020",
			"controller": "did:key:z6MkweTn1XVAiFfHjiH48oLknjNqRs43ayzguc8G8VbEAVm4",
			"publicKeyMultibase": "z6MkweTn1XVAiFfHjiH48oLknjNqRs43ayzguc8G8VbEAVm4"
		}],
		"authentication": ["did:key:z6MkweTn1XVAiFfHjiH48oLknjNqRs43ayzguc8G8VbEAVm4#z6MkweTn1XVAiFfHjiH48oLknjNqRs43ayzguc8G8VbEAVm4"],
		"assertionMethod": ["did:key:z6MkweTn1XVAiFfHjiH48oLknjNqRs43ayzguc8G8VbEAVm4#z6MkweTn1XVAiFfHjiH48oLknjNqRs43ayzguc8G8VbEAVm4"],
		"capabilityDelegation": ["did:key:z6MkweTn1XVAiFfHjiH48oLknjNqRs43ayzguc8G8VbEAVm4#z6MkweTn1XVAiFfHjiH48oLknjNqRs43ayzguc8G8VbEAVm4"],
		"capabilityInvocation": ["did:key:z6MkweTn1XVAiFfHjiH48oLknjNqRs43ayzguc8G8VbEAVm4#z6MkweTn1XVAiFfHjiH48oLknjNqRs43ayzguc8G8VbEAVm4"],
		"keyAgreement": [{
			"id": "did:key:z6MkweTn1XVAiFfHjiH48oLknjNqRs43ayzguc8G8VbEAVm4#z6LSnYW9e4Q4EXTvdjDhKyr2D1ghBfSLa5dJGBfzjG6hyPEt",
			"type": "X25519KeyAgreementKey2020",
			"controller": "did:key:z6MkweTn1XVAiFfHjiH48oLknjNqRs43ayzguc8G8VbEAVm4",
			"publicKeyMultibase": "z6LSnYW9e4Q4EXTvdjDhKyr2D1ghBfSLa5dJGBfzjG6hyPEt"
		}]
	}
}
```
</details>

The two important properties for our purposes are the `seed` and the `did`.

Copy the `seed` value and add it as described in the [Tenant](#tenants) section above, basically like so:

`TENANT_SEED_{tenant name here}=seed`

For example,

`TENANT_SEED_CHEMISTRY101=z1AjQUBZCNoiyPUC8zbbF29gLdZtHRqT6yPdFGtqJa5VfQ6`

The signing-service uses the seed to deterministically generate the signing key.

The `did` value is meant to be shared with others, typically by publishing it in a public registry for use by verifiers. Read about registries in the [registries section](#did-registries).

#### did:web generator

Setting up a did:web is a bit more complicated because - unlike a did:key - a did `document` has to be publicly available and in particular for a did:web, must be hosted at a public url.

So you can generate a did:web document using our other convenience endpoint:

`POST /did-web-generator`

In this case you'll need to POST a json document to the endpoint. Here is a curl command that will do exactly that, assuming you are running the signing-service on localhost with the default port of 4006:

```
curl --location 'localhost:4006/did-web-generator' \
--header 'Content-Type: application/json' \
--data '{"url": "https://raw.githubusercontent.com/jchartrand/didWebTest/main"}'
```

The value of 'url' property should be the url at which you will host your did:web document.
For the url above, the document will therefore need to be hosted at:

`https://raw.githubusercontent.com/jchartrand/didWebTest/main/.well-known/did.json`

But, when generating the did, leave off the '.well-known/did.json' part. That bit is assumed, according to the did:web specification.

So, that curl command will return a document something like so:

<details> 
<summary>Show code</summary>

```
{
    "seed": "z1AcNXDnko1P6QMiZ3bxsraNvVtRbpXKeE8GNLDXjBJ5UHz",
    "decodedSeed": {
        "0": 89,
        "1": 128,
        "2": 252,
        "3": 66,
        "4": 213,
        "5": 112,
        "6": 253,
        "7": 4,
        "8": 191,
        "9": 207,
        "10": 205,
        "11": 80,
        "12": 127,
        "13": 53,
        "14": 58,
        "15": 35,
        "16": 154,
        "17": 249,
        "18": 38,
        "19": 97,
        "20": 31,
        "21": 129,
        "22": 54,
        "23": 213,
        "24": 196,
        "25": 25,
        "26": 214,
        "27": 6,
        "28": 217,
        "29": 134,
        "30": 93,
        "31": 21
    },
    "did": "did:web:raw.githubusercontent.com:jchartrand:didWebTest:main",
    "didDocument": {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": "did:web:raw.githubusercontent.com:jchartrand:didWebTest:main",
        "verificationMethod": [
            {
                "id": "did:web:raw.githubusercontent.com:jchartrand:didWebTest:main#z6MkfGZKFTyxiH9HgFUHbPQigEWh8PtFaRkESt9oQLiTvhVq",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:raw.githubusercontent.com:jchartrand:didWebTest:main",
                "publicKeyMultibase": "z6MkfGZKFTyxiH9HgFUHbPQigEWh8PtFaRkESt9oQLiTvhVq"
            }
        ],
        "assertionMethod": [
            "did:web:raw.githubusercontent.com:jchartrand:didWebTest:main#z6MkfGZKFTyxiH9HgFUHbPQigEWh8PtFaRkESt9oQLiTvhVq"
        ],
        "authentication": [
            "did:web:raw.githubusercontent.com:jchartrand:didWebTest:main#z6MkfGZKFTyxiH9HgFUHbPQigEWh8PtFaRkESt9oQLiTvhVq"
        ]
    }
}
```

</details>

The generator has no tenant, so it has no configured cryptosuite: it previews the **default** suite's shape (`Ed25519VerificationKey2020`). A tenant configured with `TENANT_CRYPTOSUITE_{TENANT_NAME}=eddsa-rdfc-2022` publishes the same key with type `Multikey` — see [the published shape](#the-published-shape). The key and the `#fragment` are identical either way.

Again, as with a did:key, you'll need to set the `seed` and register the `did`, as described in the prior [did:key generator](#didkey-generator) section.

You will additionally need to copy the value of the didDocument property, i.e, from the example above

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:web:raw.githubusercontent.com:jchartrand:didWebTest:main",
  "verificationMethod": [
    {
      "id": "did:web:raw.githubusercontent.com:jchartrand:didWebTest:main#z6MkfGZKFTyxiH9HgFUHbPQigEWh8PtFaRkESt9oQLiTvhVq",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:raw.githubusercontent.com:jchartrand:didWebTest:main",
      "publicKeyMultibase": "z6MkfGZKFTyxiH9HgFUHbPQigEWh8PtFaRkESt9oQLiTvhVq"
    }
  ],
  "assertionMethod": [
    "did:web:raw.githubusercontent.com:jchartrand:didWebTest:main#z6MkfGZKFTyxiH9HgFUHbPQigEWh8PtFaRkESt9oQLiTvhVq"
  ],
  "authentication": [
    "did:web:raw.githubusercontent.com:jchartrand:didWebTest:main#z6MkfGZKFTyxiH9HgFUHbPQigEWh8PtFaRkESt9oQLiTvhVq"
  ]
}
```

If you hand-copy this for an external host, copy it for the suite that tenant is configured with — a hand-copied document is exactly the thing that drifts.

**Prefer [`GET /instance/:instanceId/did.json`](#publishing-the-did-document) over copying the document by hand.** Copying is only necessary when the DID's host is somewhere this service cannot be reached from, such as a GitHub Pages repository. Every copy is a value that can drift from the seed it came from, and one of ours did.

If you do need the copy, save the `didDocument` above in a file called did.json at the url where you'll host the document. So for our example at:

`https://raw.githubusercontent.com/jchartrand/didWebTest/main/.well-known/did.json`

You must also set the `TENANT_DIDMETHOD_{TENANT_NAME}=web` environment variable and set the `TENANT_DID_URL_{TENANT_NAME}` environement variable to the url where your `.well-known/did.json` did-document is hosted, which for this example would be:

`https://raw.githubusercontent.com/jchartrand/didWebTest/main`

#### random tenant key

NOTE: there is also an option to set the seed value for a tenant to `generate`. The system will generate a random did:key for any tenants so configured. This is really only useful for testing and experimenting since the keys are lost on restart, and the associated [DID](https://www.w3.org/TR/did-core/) for each is not registered in any public registry.

#### ecdsa-rdfc-2019 key material

`ecdsa-rdfc-2019` tenants do **not** use a seed, and there is no generator
endpoint for them. `@digitalbazaar/ecdsa-multikey`'s `generate()` accepts no
seed argument — it silently ignores one — and its raw-import path cannot
recompute a P-256 public key from the secret, so the material is minted once
and **both multibase halves are persisted**. Minting at start-up is exactly the
failure this replaces: a key minted when the process starts is a key that
changes when the process restarts.

Mint a tenant's material with:

```
npm run mint:ecdsa -- --tenant LEDGERLAB
```

It prints three values, and where each one goes matters:

| Value | Goes to |
| --- | --- |
| `publicKeyMultibase` | Your secret store, as `TENANT_KEY_PUBLIC_{TENANT_NAME}` |
| `secretKeyMultibase` | Your secret store, as `TENANT_KEY_SECRET_{TENANT_NAME}`. Never into git, a ticket or a chat message |
| `did:key` | Publishable, and the value any consumer advertising this tenant's issuer identity needs |

The key cannot be regenerated: losing the secret half means a new DID for that
tenant. Run `npm run mint:ecdsa -- --help` for the full notes, and see
[`docs/adr/2026-09-10-ecdsa-key-material-both-multibase-halves.md`](docs/adr/2026-09-10-ecdsa-key-material-both-multibase-halves.md)
for why it is shaped this way.

### DID Registries

So that a verifier knows that a credential was signed by a key that is really owned by the claimed issuer, the key (encoded as a [DID](https://www.w3.org/TR/did-core/)) has to be confirmed as really belonging to that issuer. This is typically done by adding the DID to a well known registry that the verifier checks when verifying a credential.

The DCC provides a number of registries that work with the verifiers in the Learner Credential Wallet and in the online web based [Verifier Plus](https://verifierplus.org). The DCC registries use Github for storage. To request that your [DID](https://www.w3.org/TR/did-core/) be added to a registry, submit a pull request in which you've added your [DID](https://www.w3.org/TR/did-core/) to the registry file.

### did:key

The issuer is by default set up to use the did:key implemenation of a [DID](https://www.w3.org/TR/did-core/) which is one of the simpler implementations and doesn't require that the [DID](https://www.w3.org/TR/did-core/) document be hosted anywhere.

### did:web

The did:web implementation is preferable for production becuase it allows you to rotate (change) your signing keys whithout having to update every document that points at the old keys.

#### Configuring a did:web tenant

Three environment variables, all per-tenant, all optional in general and all required together for did:web:

```
TENANT_SEED_CCP-D1=z1AeiPT496wWmo9BG2QYXeTusgFSZPNG3T9wNeTtjrQ3rCB
TENANT_DIDMETHOD_CCP-D1=web
TENANT_DID_URL_CCP-D1=https://lit-exchanges.ngrok.io/ui/ccp-d1
TENANT_CRYPTOSUITE_CCP-D1=eddsa-rdfc-2022
```

| Variable | Effect |
| --- | --- |
| `TENANT_DIDMETHOD_{TENANT_NAME}` | `web` selects did:web for this tenant. Anything else (including unset) means `key`. |
| `TENANT_DID_URL_{TENANT_NAME}` | The URL the DID document is published at, **without** the trailing `/did.json`. Determines the DID: the URL above yields `did:web:lit-exchanges.ngrok.io:ui:ccp-d1`. |
| `TENANT_CRYPTOSUITE_{TENANT_NAME}` | `eddsa-rdfc-2022` for a `DataIntegrityProof`; omit for the legacy `Ed25519Signature2020`. `ecdsa-rdfc-2019` is **not** available with did:web — see below. For did:web this also selects the **verification method type in the published document** — see [the published shape](#the-published-shape). |

These have always been read (`src/config.js`), but they were thinly documented, and that is how the incident in the next section happened. Both `Ed25519Signature2020` and `eddsa-rdfc-2022` work with did:web.

#### Publishing the DID document

A did:web DID only resolves if a document is served at the identifier's own URL — for the tenant above, `https://lit-exchanges.ngrok.io/ui/ccp-d1/did.json`.

**Do not hand-copy the document there.** The [did:web generator](#didweb-generator) section describes copying the `didDocument` property into a file, which works and is what an external host like GitHub Pages needs, but it produces a hand-maintained copy of a value that is otherwise derived. We shipped exactly that copy once, it drifted from the configured seed, and the published issuer identifier and the actual signing key disagreed for an entire milestone because nothing ever compared them.

So this service publishes the real thing:

```
GET /instance/:instanceId/did.json
```

```
curl localhost:4006/instance/ccp-d1/did.json
```

- The document is **derived on every request** from the same seed and URL, through the same driver call, that produce the signing key. There is no stored copy and no way to override it, so "issuer says one thing, key says another" cannot be represented.
- **No authentication.** A DID document is public by definition and carries only public key material.
- **404 for a `did:key` tenant** (nothing to host) or an unknown tenant. The tenant name is already in the URL the caller constructed, so the two are not distinguished.
- Returns a plain DID document with `Content-Type: application/json` — no envelope, because the caller is a DID resolver.

##### The published shape

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1"
  ],
  "id": "did:web:lit-exchanges.ngrok.io:ui:ccp-d1",
  "verificationMethod": [
    {
      "id": "did:web:lit-exchanges.ngrok.io:ui:ccp-d1#z6MkfZN9…",
      "type": "Multikey",
      "controller": "did:web:lit-exchanges.ngrok.io:ui:ccp-d1",
      "publicKeyMultibase": "z6MkfZN9…"
    }
  ],
  "assertionMethod": ["did:web:lit-exchanges.ngrok.io:ui:ccp-d1#z6MkfZN9…"],
  "authentication": ["did:web:lit-exchanges.ngrok.io:ui:ccp-d1#z6MkfZN9…"]
}
```

The verification method's `type` and the second `@context` entry follow the tenant's `TENANT_CRYPTOSUITE_{TENANT_NAME}`, because the document has to describe the key the way the proof will reference it:

| `TENANT_CRYPTOSUITE_{TENANT_NAME}` | Verification method `type` | Second `@context` entry |
| --- | --- | --- |
| *(unset)* / `Ed25519Signature2020` | `Ed25519VerificationKey2020` | `https://w3id.org/security/suites/ed25519-2020/v1` |
| `eddsa-rdfc-2022` | `Multikey` | `https://w3id.org/security/multikey/v1` |
| `ecdsa-rdfc-2019` | — | refused, [see below](#ecdsa-rdfc-2019-is-didkey-only) |

**The key, the `#fragment` and the DID do not change with the suite** — only the type and the context do. An already-issued credential's `proof.verificationMethod` keeps pointing at the published method.

**This shape is normalised from the driver's output, not composed.** `@interop/did-web-resolver@5.0.0` returns a document that embeds the whole method inside `assertionMethod`, emits no top-level `verificationMethod` array, and declares an x25519 context it never backs with a `keyAgreement` key. That form is legal — DID Core §5.3.1 allows an embedded method — but a third-party wallet is entitled to reject it, and this service is used to test wallets, so a wallet's failure has to be the wallet's fault. `src/didWeb.js` therefore **moves** the method the driver produced into `verificationMethod`, references it by fragment from `assertionMethod` and `authentication`, drops the unused x25519 context, and substitutes the suite's `type`. It never builds a method out of separately-held key material: a document composed beside the signing path is the drift this endpoint exists to prevent. If the driver's output shape ever changes, the normaliser throws a 500 rather than serving a document with no key in it. See [`docs/adr/2026-08-11-did-web-document-normalisation.md`](docs/adr/2026-08-11-did-web-document-normalisation.md).

Anything asserting on the published document should read `verificationMethod[0]`.

If the host that answers on the DID's domain is not this service — it usually is not, since the signing service is normally not public — that host should proxy this endpoint rather than keep a copy. [`dcc-transaction-service`](https://github.com/skybridgeskills/dcc-transaction-service) does exactly this for the tunnelled host, deriving the path and the signing tenant from its own issuer-instance configuration.

#### ecdsa-rdfc-2019 is did:key only

`TENANT_CRYPTOSUITE_{TENANT_NAME}=ecdsa-rdfc-2019` together with `TENANT_DIDMETHOD_{TENANT_NAME}=web` is **refused**, both when signing and when publishing, with:

> ecdsa-rdfc-2019 is supported for did:key only. The did:web driver cannot express a P-256 verification method, and issuing one would publish a DID document that misdescribes the key.

This is deliberate, not a gap. The did:web driver composes a document whose `@context` is hardcoded to the Ed25519 and X25519 suite contexts — no Multikey, no data-integrity context — and it emits no verification method for an ECDSA key at all. Publishing a P-256 key inside that document would look fine here and fail, or worse verify ambiguously, at a relying party. Supporting it means composing the document ourselves or replacing the resolver. `ecdsa-rdfc-2019` with did:key works.

Note that the normalisation described above does **not** open this door. It re-expresses a method the driver actually produced; for an `ecdsa-rdfc-2019` tenant the driver still produces an *Ed25519* key, so restyling the document would publish a key the tenant never signs with — the same mis-issuance, wearing a better-shaped document. Publication is refused before a suite is even selected.

## Usage

This express app can be run a few different ways:

#### NPM

You can start the script using NPM, like is done with the `start` script in package.json

#### Directly from DockerHub

You can directly from the DockerHub image, using a default configuration, with:

`docker run -dp 4006:4006 digitalcredentials/signing-service:0.3.0`

To run it with your own configuration (like with your own signing keys):

``docker run --env-file .env -dp 4006:4006 digitalcredentials/signing-service:0.3.0`

where the `.env` file contains your environment variables. See [.env.example](./.env.example).

#### With Docker Compose

See how we do that in the [DCC issuer-coordinator](https://github.com/digitalcredentials/issuer-coordinator)

Note that to run this with Docker, you'll of course need to install Docker, which is very easy with the [Docker installers for Windows, Mac, and Linux](https://docs.docker.com/engine/install/).

### Sign an OID4VP request object

```
POST /instance/:instanceId/openid4vp/request-object/sign
```

⚠️ **This service signs something that is not a credential, and that is
deliberate.** OID4VP §5.9.3's `decentralized_identifier` Client Identifier
Prefix identifies a verifier by a DID, and the JOSE `kid` in its signed request
object must name a key in that DID document's `verificationMethod`. **This
service is the only component that derives both the published document and the
signing key from one seed** — `didWeb.js` exists for precisely that invariant.
Holding the key anywhere else would put the document and the key in different
processes with nothing comparing them, which is [gap H1](#didweb) with a network
in the middle.

The body is the request object's claims; the response is a compact JWS served as
`application/oauth-authz-req+jwt`, unwrapped, so the caller can serve those bytes
verbatim at its `request_uri`.

```
curl --location 'http://localhost:4006/instance/test/openid4vp/request-object/sign' --header 'Content-Type: application/json' --data-raw '{"response_type":"vp_token","response_mode":"direct_post","client_id":"decentralized_identifier:did:web:example.com","nonce":"n","state":"s"}'
```

**What it signs with:** the tenant's existing seed. No new keys, no new tenants,
no new DIDs. ⚠️ The DID is an **entity identity, not a role identity** — some
organisations verify only, some issue only, and this service signs on behalf of
the entity whatever it happens to be acting as. Do not let documentation call it
"the issuer DID" in a verifier context.

**The `kid`** is read from the tenant's published `did.json`, never composed from
`did + '#' + something`. A composed `kid` would be a second statement about which
key signs.

⚠️ **The algorithm is EdDSA and it is forced, not chosen.** See
[`ecdsa-rdfc-2019` is did:key only](#ecdsa-rdfc-2019-is-didkey-only): the
`did:web` driver cannot express a P-256 verification method, so an ECDSA
`did:web` tenant is refused here with the same shared message the signing and
publication paths use. **ES256 is the de-facto default for OID4VP request-object
signing in the mDL/EUDI world**, so a conformant signed arm may prove less
interoperable than an unsigned one — that is a thing to measure, and no P-256
path was added to pre-empt it.

**Refusals are named, and there is no unsigned fallback.** An unknown tenant, a
`did:key` tenant (it publishes no document at a URL), a refused suite, or an
empty body each return a named error. ⚠️ An unsigned result from a *sign*
endpoint would look like success, and the verifier separately serves a genuinely
unsigned `alg: none` request object as a registered accommodation — the two must
never be confusable.

See [the ADR](docs/adr/2026-08-25-oid4vp-request-object-signing.md).

### Sign a credential

Try it out with this CURL command, which you simply paste into the terminal (once you've got your issuer running on your computer, as described above):

<details> 
<summary>Show code</summary>
  
```
curl --location 'http://localhost:4006/instance/test/credentials/sign' \
--header 'Content-Type: application/json' \
--data-raw '{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.2.json"
  ],
  "id": "urn:uuid:2fe53dc9-b2ec-4939-9b2c-0d00f6663b6c",
  "type": [
    "VerifiableCredential",
    "OpenBadgeCredential"
  ],
  "name": "DCC Test Credential",
  "issuer": {
    "type": [
      "Profile"
    ],
    "id": "did:key:z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC",
    "name": "Digital Credentials Consortium Test Issuer",
    "url": "https://dcconsortium.org",
    "image": "https://user-images.githubusercontent.com/752326/230469660-8f80d264-eccf-4edd-8e50-ea634d407778.png"
  },
  "issuanceDate": "2023-08-02T17:43:32.903Z",
  "credentialSubject": {
    "type": [
      "AchievementSubject"
    ],
    "achievement": {
      "id": "urn:uuid:bd6d9316-f7ae-4073-a1e5-2f7f5bd22922",
      "type": [
        "Achievement"
      ],
      "achievementType": "Diploma",
      "name": "Badge",
      "description": "This is a sample credential issued by the Digital Credentials Consortium to demonstrate the functionality of Verifiable Credentials for wallets and verifiers.",
      "criteria": {
        "type": "Criteria",
        "narrative": "This credential was issued to a student that demonstrated proficiency in the Python programming language that occurred from **February 17, 2023** to **June 12, 2023**."
      },
      "image": {
        "id": "https://user-images.githubusercontent.com/752326/214947713-15826a3a-b5ac-4fba-8d4a-884b60cb7157.png",
        "type": "Image"
      }
    },
    "name": "Jane Doe"
  }
}'
```
</details>

This should return a fully formed and signed credential printed to the terminal, that should look something like this (it may be all smushed up, but you can format it in something like [json lint](https://jsonlint.com):

<details> 
<summary>Show code</summary>
  
```
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.2.json",
        "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    "id": "urn:uuid:2fe53dc9-b2ec-4939-9b2c-0d00f6663b6c",
    "type": [
        "VerifiableCredential",
        "OpenBadgeCredential"
    ],
    "name": "DCC Test Credential",
    "issuer": {
        "type": [
            "Profile"
        ],
        "id": "did:key:z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q",
        "name": "Digital Credentials Consortium Test Issuer",
        "url": "https://dcconsortium.org",
        "image": "https://user-images.githubusercontent.com/752326/230469660-8f80d264-eccf-4edd-8e50-ea634d407778.png"
    },
    "issuanceDate": "2023-08-02T17:43:32.903Z",
    "credentialSubject": {
        "type": [
            "AchievementSubject"
        ],
        "achievement": {
            "id": "urn:uuid:bd6d9316-f7ae-4073-a1e5-2f7f5bd22922",
            "type": [
                "Achievement"
            ],
            "achievementType": "Diploma",
            "name": "Badge",
            "description": "This is a sample credential issued by the Digital Credentials Consortium to demonstrate the functionality of Verifiable Credentials for wallets and verifiers.",
            "criteria": {
                "type": "Criteria",
                "narrative": "This credential was issued to a student that demonstrated proficiency in the Python programming language that occurred from **February 17, 2023** to **June 12, 2023**."
            },
            "image": {
                "id": "https://user-images.githubusercontent.com/752326/214947713-15826a3a-b5ac-4fba-8d4a-884b60cb7157.png",
                "type": "Image"
            }
        },
        "name": "Jane Doe"
    },
    "proof": {
        "type": "Ed25519Signature2020",
        "created": "2023-10-05T11:17:41Z",
        "verificationMethod": "did:key:z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q#z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q",
        "proofPurpose": "assertionMethod",
        "proofValue": "z5fk6gq9upyZvcFvJdRdeL5KmvHr69jxEkyDEd2HyQdyhk9VnDEonNSmrfLAcLEDT9j4gGdCG24WHhojVHPbRsNER"
    }
}
```
</details>

NOTE: CURL can get a bit clunky if you want to experiment - you might consider trying [Postman](https://www.postman.com/downloads/) which makes it a bit easier to construct and send http calls.

### VCALM Issue Endpoint

The service also supports the VCALM (Verifiable Credentials API for Learner Records Management) `/credentials/issue` endpoint. This endpoint is similar to the `/credentials/sign` endpoint but follows the VCALM specification format and supports authentication.

#### POST /credentials/issue

This endpoint follows the VCALM specification for issuing credentials. The tenant is **not** in the URL; it is determined from `Authorization`.

**Authentication:**

An `Authorization` header is always required. Whether a valid secret is required depends on the tenant:

- **Basic Auth**: `Authorization: Basic <base64(username:password)>` where `username` is the tenant name (same as the legacy path segment, case-insensitive). If `TENANT_AUTH_TOKEN_{TENANT_NAME}` is set, `password` must match it exactly. If it is **not** set, the tenant is **open** on `/credentials/issue`: **any** password is accepted once the tenant name matches. This tokenless mode is intentional (it preserves frictionless local/dev use), so setting a token is what actually gates a tenant behind authentication. The three default tenants (`test`, `testing`, `random`) ship without tokens and are therefore open. On config load, the service logs a consolidated `[auth]` warning listing every tokenless (open) tenant.
- **Bearer Token**: `Authorization: Bearer <token>` where `<token>` equals that tenant's `TENANT_AUTH_TOKEN_{TENANT_NAME}`. The service maps the token to a tenant internally; **use a distinct token per tenant.** If two tenants share a token, only one wins the reverse lookup and the service logs an `[auth]` warning at config load.

See the [tokenless-auth-policy ADR](docs/adr/2026-07-06-credentials-issue-tokenless-auth-policy.md) for the rationale behind keeping tokenless tenants open rather than fail-closed.

**Headers:**

- `Authorization: Bearer <token>` or `Authorization: Basic <base64(username:password)>` (required)
- `Content-Type: application/json`

**Request Body:**

```json
{
  "credential": {
    "@context": ["https://www.w3.org/2018/credentials/v1", ...],
    "type": ["VerifiableCredential", ...],
    "issuer": {...},
    "credentialSubject": {...}
  }
}
```

**Example with Bearer Token:**

```bash
curl --location 'http://localhost:4006/credentials/issue' \
--header 'Authorization: Bearer mysecrettoken' \
--header 'Content-Type: application/json' \
--data '{
  "credential": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential"],
    "issuer": {"id": "did:example:123", "name": "Test"},
    "credentialSubject": {"id": "did:example:456"}
  }
}'
```

**Example with Basic Auth:**

```bash
curl --location 'http://localhost:4006/credentials/issue' \
--header 'Authorization: Basic dGVzdDpteXNlY3JldHRva2Vu' \
--header 'Content-Type: application/json' \
--data '{
  "credential": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential"],
    "issuer": {"id": "did:example:123", "name": "Test"},
    "credentialSubject": {"id": "did:example:456"}
  }
}'
```

Note: In the Basic Auth example, `dGVzdDpteXNlY3JldHRva2Vu` is the base64 encoding of `test:mysecrettoken` (username:password).

The cryptosuite used for signing is determined by the `TENANT_CRYPTOSUITE_{TENANT_NAME}` configuration. If not specified, the service defaults to `Ed25519Signature2020`.

### Learner Credential Wallet

You might now consider importing your new credential into the [Learner Credential Wallet](https://lcw.app) to see how credentials can be managed and shared from an app based wallet. Simply copy the verifiable credential you just generated and paste it into the text box on the 'add credential' screen of the wallet.

## Revocation

The signing-service doesn't on its own provide a revocation mechanism. To enable revocation, you'll want to combine the signing-service with a revocation system like the [DCC status-service](https://github.com/digitalcredentials/status-service), but we've already done exactly that with the [DCC issuer-coordinator](https://github.com/digitalcredentials/issuer-coordinator).

## Versioning

The signing-service is primarily intended to run as a docker image within a docker compose network, typically as part of a flow that is orchestrated by the [DCC Issuer Coordinator](https://github.com/digitalcredentials/issuer-coordinator) and the [DCC Workflow Coordinator](https://github.com/digitalcredentials/workflow-coordinator).

For convenience we've published the images for the signing-service and the other services used by the coordinators, as well as for the coordinators themselves, to Docker Hub so that you don't have to build them locally yourself from the github repositories.

The images on Docker Hub will of course at times be updated to add new functionality and fix bugs. Rather than overwrite the default (`latest`) version on Docker Hub for each update, we've adopted the [Semantic Versioning Guidelines](https://semver.org) with our docker image tags.

We DO NOT provide a `latest` tag so you must provide a tag name (i.e, the version number) for the images in your docker compose file.

To ensure you've got compatible versions of the services and the coordinator, take a look at our [sample compose files](https://github.com/digitalcredentials/docs/blob/main/deployment-guide/DCCDeploymentGuide.md#docker-compose-examples).

If you do ever want to work from the source code in the repository and build your own images, we've tagged the commits in Github that were used to build the corresponding Docker image. So a github tag of v0.1.0 coresponds to a docker image tag of 0.1.0

## Logging

We support the following log levels:

```
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  verbose: 4,
  debug: 5,
  silly: 6
```

Logging is configured with environment variables, as defined in the [Environment Variables](#environment-variables) section.

By default, everything is logged to the console (log level `silly`).

All http calls to the service are logged by default, which might bloat the log. You can disable access logging with:

`ENABLE_ACCESS_LOGGING=false`

You may set the log level for the application as whole, e.g.,

`LOG_LEVEL=http`

Which would only log messages with severity 'http' and all below it (info, warn, error).

The default is to log everything (level 'silly').

You can also set the log level for console logging, e.g.,

`CONSOLE_LOG_LEVEL=debug`

This would log everything for severity 'debug' and lower (i.e., verbose, http, info, warn, error). This of course assumes that you've set the log level for the application as a whole to at least the same level.

The default log level for the console is 'silly', which logs everything.

There are also two log files that can be enabled:

- errors (only logs errors)
- all (logs everything - all log levels)

Enable each log by setting an env variable for each, indicating the path to the appropriate file, like this example:

```
LOG_ALL_FILE=logs/all.log
ERROR_LOG_FILE=logs/error.log
```

## Health Check

Docker has a [HEALTHCHECK](https://docs.docker.com/reference/dockerfile/#healthcheck) option for monitoring the
state (health) of a container. We've included an endpoint `GET healthz` that checks the health of the signing service (by running a test signature). The endpoint can be directly specified in a CURL or WGET call on the HEALTHCHECK, but we also provide a [healthcheck.js](./healthcheck.js) function that can be similarly invoked by the HEALTHCHECK and which itself hits the `healthz` endpoint, but additionally provides options for both email and Slack notifications when the service is unhealthy.

You can see how we've configured the HEALTHCHECK in our [example compose files](https://github.com/digitalcredentials/docs/blob/main/deployment-guide/DCCDeploymentGuide.md#docker-compose-examples). Our compose files also include an example of how to use [autoheal](https://github.com/willfarrell/docker-autoheal) together with HEALTHCHECK to restart an unhealthy container.

If you want notifications sent to a Slack channel, you'll have to set up a Slack [web hook](https://api.slack.com/messaging/webhooks).

If you want notifications sent to an email address, you'll need an SMTP server to which you can send emails, so something like sendgrid, mailchimp, mailgun, or even your own email account if it allows direct SMTP sends. Gmail can apparently be configured to so so.

## Development

### Installation

Clone code then cd into directory and:

```
npm install
npm run dev
```

If for whatever reason you need to run the server over https, you can set the `ENABLE_HTTPS_FOR_DEV` environment variable to true. Note, though, that this should ONLY be used for development.

### Testing

Testing uses supertest, jest, and nock to test the endpoints. To run tests:

`npm run test`

Because the revocation (status) system uses github to store status, calls are made out to github during issuance. Rather than have to make these calls for every test, and possibly in cases where outgoing http calls aren't ideal, we've used [nock](https://github.com/nock/nock) to mock out the http calls to the github api, so that the actual calls needn't be made - nock instead returns our precanned replies. Creating mocks can be time consuming, though, so we've also opted to use the recording feature of nock which allows us to run the tests in 'record' mode which will make the real calls out to Github, and record the results so they can be used for future calls.

## Contribute

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[MIT License](LICENSE.md) © 2024 Digital Credentials Consortium.
