# `did:oyd` Resolver

[![npm](https://img.shields.io/npm/v/oydid-did-resolver)](https://www.npmjs.com/package/oydid-did-resolver)

Resolver plugin for [`did-resolver`](https://github.com/decentralized-identity/did-resolver)
that resolves [OYDID](https://github.com/OwnYourData/oydid) identifiers.

The `did:oyd` method links the identifier cryptographically to the DID Document,
and through a cryptographically linked provenance log it resolves to the latest
valid version of that document. Verifying that chain is the job of an OYDID
resolver; this library is the client for one and speaks the
[HTTP(S) binding](https://www.w3.org/TR/did-resolution/#bindings-https) of the
DID Resolution specification.

Example identifier:
`did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh`

* Method specification: <https://ownyourdata.github.io/oydid/>
* Resolver implementation: <https://github.com/OwnYourData/oydid>
* Public resolver used by default: <https://resolver.ownyourdata.eu>

## Installation

```bash
npm install oydid-did-resolver did-resolver
```

Requires Node.js 18 or newer (the library uses the platform `fetch`). It has **no
runtime dependencies**; `did-resolver` is a peer dependency and is only needed
for the aggregator — the standalone `resolve()` export works without it.

## Usage

```javascript
const { Resolver } = require('did-resolver')
const { getResolver } = require('oydid-did-resolver')

const resolver = new Resolver({ ...getResolver() })

const result = await resolver.resolve('did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh')
console.log(JSON.stringify(result, undefined, 2))
```

### Configuration

`getResolver()` takes either a resolver base URL or an options object:

```javascript
getResolver('https://oydid-resolver.data-container.net')

getResolver({
  resolverUrl: 'https://resolver.ownyourdata.eu', // default
  path: '/1.0/identifiers/',                      // default; '/1.0/resolve/' also works
  timeout: 10000,                                 // milliseconds, default
  headers: { Authorization: 'Bearer …' },         // for a private resolver
  allowLocationSuffix: true,                      // default, see "Location suffix"
})
```

`path` defaults to `/1.0/identifiers/` because every OYDID resolver and the
Universal Resolver serve it and it always answers with a full DID Resolution
Result. OYDID resolvers from version 0.5.2 on also offer the content-negotiated
`/1.0/resolve/`.

### Without the aggregator

```javascript
const { resolve } = require('oydid-did-resolver')

const result = await resolve('did:oyd:zQmaBZ…', { timeout: 5000 })
```

## Result

`resolve()` **never throws**. Transport failures, malformed input and resolver
errors are all reported as `didResolutionMetadata.error`, as the DID Resolution
specification requires. A successful resolution of the example DID above:

```json
{
  "didResolutionMetadata": {
    "contentType": "application/did+ld+json"
  },
  "didDocument": {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    "id": "did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh",
    "verificationMethod": [
      {
        "id": "did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh#key-doc",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh",
        "publicKeyMultibase": "z6MusYB5iT5krCHYsZ76EzBaTdRwGKsaBhMcSbrXaPJgkuRQ"
      },
      {
        "id": "did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh#key-rev",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh",
        "publicKeyMultibase": "z6Mv7EYihbAat6Wq7GsjNsjcxt58dZT8fmsRjQGTkYamYrjB"
      }
    ],
    "service": [
      {
        "id": "did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh#payload",
        "type": "Custom",
        "serviceEndpoint": "https://oydid.ownyourdata.eu",
        "payload": { "simple": "example" }
      }
    ]
  },
  "didDocumentMetadata": {
    "canonicalId": "did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh",
    "versionId": "zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh",
    "created": "2022-01-03T15:45:36Z",
    "registry": "https://oydid.ownyourdata.eu",
    "log_hash": "zQmVwMvovLy5KNYHHVHQ1wv8J7y9L6UPE8eyU4tzypFWtYe",
    "log": [
      {
        "ts": 1641224736,
        "op": 2,
        "doc": "zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh",
        "sig": "z3Kb5qeReCqr3ftxpf2i5UypUwrzrVkyspMtaDcb6e9YdHVSptcAFgvwbgk3qWqspTcGiKDYKXZZh8g6XyM2WPmNp",
        "previous": []
      },
      {
        "ts": 1641224736,
        "op": 0,
        "doc": "zQmT8SG7a238bF7wdV7LdrEAQpimqhKGor7CQsjtCYdZdTS",
        "sig": "z63hu8LseptBrvB2kEDwhPP35sBj7JDDJsEDW85cjRkrjjac9ZV3HxPW9NVKewHcQYwrVLVsnDCcm1RjbEARE5rJU",
        "previous": []
      }
    ],
    "document_log_id": 0,
    "termination_log_id": 1,
    "keys": [ "…" ]
  }
}
```

`log`, `log_hash`, `registry`, `document_log_id` and `termination_log_id` are
method-specific metadata; `keys` follows a Universal Resolver convention.

### Deactivated DIDs

A revoked DID resolves **successfully**. Per DID Core §7.1.3 the answer is
"deactivated", not an error:

```json
{
  "didResolutionMetadata": {},
  "didDocument": null,
  "didDocumentMetadata": { "deactivated": true }
}
```

This is produced both for an HTTP 200 answer carrying that metadata and for an
HTTP 410 answer. A resolver configured with `REVOKED_HTTP_STATUS=404` reports
`notFound` instead — over HTTP that case cannot be told apart from an identifier
that never existed.

### Errors

| `didResolutionMetadata.error` | Cause |
|---|---|
| `invalidDid` | the input is not a syntactically valid DID, or the resolver answered 400 |
| `invalidDidUrl` | the DID URL has a path — `did:oyd` does not define one |
| `notFound` | the resolver does not know this DID (HTTP 404) |
| `methodNotSupported` | the DID is not a `did:oyd` DID |
| `featureNotSupported` | `versionId` / `versionTime` was requested (see below), or the resolver answered 501 |
| `internalError` | the resolver was unreachable, timed out, or answered with 5xx or a body that is not JSON |

`errorMessage` carries a human-readable detail. When the resolver itself states
an error in `didResolutionMetadata`, that error is passed through unchanged.

## Limitations

**Location suffix.** OYDID allows an identifier to name where its log lives:
`did:oyd:<hash>@<location>`. `@` is not an `idchar` in the DID ABNF, so such a
string is not a valid DID and generic parsers — including the one inside
`did-resolver` — reject it. Through `Resolver.resolve()` it therefore fails with
`invalidDid` before this library sees it. The standalone `resolve()` export
accepts it anyway; the conformant spelling is the percent-encoded `%40`.

**Versions.** `?versionId=` and `?versionTime=` are not defined for `did:oyd`.
They are reported as `featureNotSupported` rather than silently ignored. A
specific version is addressed directly, as `did:oyd:<versionId>`.

**Resolution only.** Creating, updating and deactivating DIDs is not part of this
library. Use the [OYDID command line tool](https://github.com/OwnYourData/oydid/tree/main/cli),
the [Ruby gem](https://github.com/OwnYourData/oydid/tree/main/ruby-gem), or the
registrar API.

## Development

```bash
npm install
npm run typecheck    # tsc --noEmit
npm test             # build, then 46 offline tests (fetch is stubbed)
npm run test:live    # additionally 4 tests against a real resolver
```

`OYDID_RESOLVER` and `OYDID_TEST_DID` point the live tests at another endpoint:

```bash
OYDID_LIVE=1 OYDID_RESOLVER=https://oydid-resolver.data-container.net node --test
```

## License

[Apache 2.0 License - OwnYourData.eu](https://raw.githubusercontent.com/OwnYourData/oydid/main/LICENSE)
