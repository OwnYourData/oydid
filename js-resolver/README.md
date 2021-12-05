# `did:oyd` Resolver

This library is intended to use [OYDID](https://github.com/oydeu/oydid) as fully self-managed Decentralized Identifiers and wrap them in a DID Document

It supports the proposed [Decentralized Identifiers](https://w3c.github.io/did-core/#identifier) spec from the [W3C Credentials Community Group](https://w3c-ccg.github.io/).

It requires the [`did-resolver`](https://github.com/decentralized-identity/did-resolver) library, which is the primary interface for resolving DIDs. Also it is dependent on a hosted resolver that can resolve OYDID DIDs. Such an implementation can be found here: https://github.com/OwnYourData/oydid

There is also a publicly available resolver at https://oydid-resolver.data-container.net, which is used as fallback resolver within this library.

## DID method

The `did:oyd` method links the identifier cryptographically to the DID Document and through also cryptographically linked provenance information in a public log it ensures resolving to the latest valid version of the DID Document. Read more about OYDID at https://github.com/OwnYourData/oydid

Example:    
`did:oyd:zQmZ8DEGQtJcpoQDMKYJkTiQn9dQLM2QzvmDQXuj8vCfvdj`

## Installation

Node.js and npm are prerequisites for installation.

```bash
npm install oydid-did-resolver
```

## Usage

The library presents a `resolve()` functions that returns a `Promise` returning the  DID document. It is not meant to be used directly but through the **`did-resolver`** aggregator.    

```javascript
const { Resolver } = require('did-resolver');
const oydid = require('oydid-did-resolver');

const resolver = new Resolver({
  ...oydid.getResolver()
});

// resolve test-did
resolver.resolve('did:oyd:zQmZ8DEGQtJcpoQDMKYJkTiQn9dQLM2QzvmDQXuj8vCfvdj').then(data =>
  console.log(JSON.stringify(data, undefined, 2))
);
```

## DID Document

The did resolver takes the identifier and queries existing OYDID repositories to retrieve a DID document with the hash representation of the given identifier.

A minimal DID document using the above sample DID looks like this:

```
{
	"didResolutionMetadata": {},
	"didDocument": {
		"@context": "https://www.w3.org/ns/did/v1",
		"id": "did:oyd:zQmZ8DEGQtJcpoQDMKYJkTiQn9dQLM2QzvmDQXuj8vCfvdj",
		"verificationMethod": [{
			"id": "did:oyd:zQmZ8DEGQtJcpoQDMKYJkTiQn9dQLM2QzvmDQXuj8vCfvdj",
			"type": "Ed25519VerificationKey2018",
			"controller": "did:oyd:zQmZ8DEGQtJcpoQDMKYJkTiQn9dQLM2QzvmDQXuj8vCfvdj",
			"publicKeyBase58": "zJ28iS4E3c1vVwvxnVFqdpxvw8kA6bZVz6PqaWCg3d96F"
		}],
		"keyAgreement": [{
			"id": "did:oyd:zQmZ8DEGQtJcpoQDMKYJkTiQn9dQLM2QzvmDQXuj8vCfvdj",
			"type": "X25519KeyAgreementKey2019",
			"controller": "did:oyd:zQmZ8DEGQtJcpoQDMKYJkTiQn9dQLM2QzvmDQXuj8vCfvdj",
			"publicKeyBase58": "z5NewiTaFLojX1VehgZKpNNKFKt7TpfF55iHE4cKhZCCH"
		}],
		"service": [{
			"services": [{
				"foo": "bar"
			}]
		}]
	},
	"didDocumentMetadata": {
		"did": "zQmZ8DEGQtJcpoQDMKYJkTiQn9dQLM2QzvmDQXuj8vCfvdj",
		"registry": "https://oydid.ownyourdata.eu",
		"log_hash": "zQmdtRUF646gzvmmv7aFCqfhcv4ABB2J1pzq4t7VKdaHCMC",
		"log": [{
			"ts": 1633297715,
			"op": 2,
			"doc": "zQmZ8DEGQtJcpoQDMKYJkTiQn9dQLM2QzvmDQXuj8vCfvdj",
			"sig": "z41WRGuR8pFkJ5UWkW6W42fEsE8s3ksfaUPyVf1MdFzRpuu2HmCbN7zQcEHbBMiCiTJV2tWbFE2exgaSmobWFm5vW",
			"previous": []
		}, {
			"ts": 1633297715,
			"op": 0,
			"doc": "zQmTTWppEjD2WdJ47PDNQR3gEZ2bhV4Q6G4KH7LYS4r73di",
			"sig": "z3XEuFmc7v4WReooRdCFNsYc74SCDjGwQQzwVuuJe79ARaMwKqp9v4ED4tQxsukwxJD5bGdHDvtKzce9DNYFZ3CrC",
			"previous": []
		}],
		"document_log_id": 0,
		"termination_log_id": 1
	}
}
```