# Universal Resolver Driver: `did:oyd`

This is a [Universal Resolver](https://github.com/decentralized-identity/universal-resolver/) driver for **did:oyd** identifiers.

## Specifications

* [Decentralized Identifiers](https://w3c.github.io/did-core/)
* [OYDID Method Specification](https://ownyourdata.github.io/oydid/)

## Example DIDs

```
did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh
did:oyd:zQmNauTUUdkpi5TcrTZ2524SKM8dJAzuuw4xfW13iHrtY1W%40did2.data-container.net
```

## Endpoints

All endpoints are read-only `GET` requests; `<did>` is percent-encoded where necessary.

| Endpoint | Answer |
|---|---|
| `/1.0/identifiers/<did>` | DID Resolution Result (`application/ld+json`) — binding used by the [Universal Resolver](https://github.com/decentralized-identity/universal-resolver/) driver configuration |
| `/1.0/resolve/<did>` | `resolve` function of the [DID Resolution](https://w3c.github.io/did-resolution/#bindings-https) spec, content negotiated (see below) |
| `/1.0/resolveRepresentation/<did>` | `resolveRepresentation` function — the DID Document, by default as `application/did+ld+json` |
| `/1.0/dereference/<did-url>` | `dereference` function — supports a plain DID and a fragment (`...%23key-doc`); DID URL path and query are answered with `501 notSupported` |
| `/version` | service and `oydid` gem version |

The unversioned paths `/resolve/<did>`, `/resolveRepresentation/<did>` and
`/dereference/<did-url>` are kept as aliases.

### Content negotiation

`/1.0/resolve/` and `/1.0/resolveRepresentation/` evaluate the `Accept` header
and answer `Vary: Accept`:

| `Accept` | Answer |
|---|---|
| `application/did-resolution` | DID Resolution Result |
| `application/ld+json;profile="https://w3id.org/did-resolution"` | DID Resolution Result (legacy media type, sent by the Universal Resolver) |
| `application/did`, `application/did+ld+json`, `application/did+json` | DID Document only |
| absent or `*/*` | Resolution Result on `/1.0/resolve/`, DID Document on `/1.0/resolveRepresentation/` |

Status codes: `200` on success, `404` for an unknown DID, `410` for a revoked
DID (`REVOKED_HTTP_STATUS=404` turns this into a `404`), `501` for an
unsupported DID URL, `500` otherwise.

```
curl -H "Accept: application/did-resolution" \
     https://resolver.ownyourdata.eu/1.0/resolve/did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh
```

## Build and Run (Docker)

```
docker build -f ./docker/Dockerfile . -t oydeu/oydid-resolver
docker run -p 8080:3000 oydeu/oydid-resolver
curl -X GET http://localhost:8080/1.0/identifiers/did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh
```

Docker images are available here: https://hub.docker.com/r/oydeu/oydid-resolver

## OYDID Universal Resolver Driver

Please report bugs and suggestions for new features using the [GitHub Issue-Tracker](https://github.com/OwnYourData/oydid/issues) and follow the [Contributor Guidelines](https://github.com/twbs/ratchet/blob/master/CONTRIBUTING.md).

If you want to contribute, please follow these steps:

1. Fork it!
2. Create a feature branch: `git checkout -b my-new-feature`
3. Commit changes: `git commit -am 'Add some feature'`
4. Push into branch: `git push origin my-new-feature`
5. Send a Pull Request

&nbsp;    

## License

[Apache 2.0 License - OwnYourData.eu](https://raw.githubusercontent.com/OwnYourData/oydid/main/LICENSE)
