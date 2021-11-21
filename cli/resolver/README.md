# Universal Resolver Driver: did:oyd

This is a [Universal Resolver](https://github.com/decentralized-identity/universal-resolver/) driver for **did:oyd** identifiers.

## Specifications

* [Decentralized Identifiers](https://w3c.github.io/did-core/)
* [DID Method Specification](https://github.com/OwnYourData/did-cmd/blob/main/docs/did-spec.md)

## Example DIDs

```
did:oyd:zQmZ8DEGQtJcpoQDMKYJkTiQn9dQLM2QzvmDQXuj8vCfvdj
did:oyd:zQmNUV1MJ5xKkFm6Lc9EKqAauGzbKP7amvbyxsx79mKwqPB
```

## Build and Run (Docker)

```
docker build -f ./docker/Dockerfile . -t oydeu/oydid-resolver
docker run -p 8080:3000 oydeu/oydid-resolver
curl -X GET http://localhost:8080/1.0/identifiers/did:oyd:zQmZ8DEGQtJcpoQDMKYJkTiQn9dQLM2QzvmDQXuj8vCfvdj
```


## OYDID Universal Resolver Driver

Please report bugs and suggestions for new features using the [GitHub Issue-Tracker](https://github.com/OwnYourData/did-cmd/issues) and follow the [Contributor Guidelines](https://github.com/twbs/ratchet/blob/master/CONTRIBUTING.md).

If you want to contribute, please follow these steps:

1. Fork it!
2. Create a feature branch: `git checkout -b my-new-feature`
3. Commit changes: `git commit -am 'Add some feature'`
4. Push into branch: `git push origin my-new-feature`
5. Send a Pull Request

&nbsp;    

## Lizenz

[MIT License 2021 - OwnYourData.eu](https://raw.githubusercontent.com/OwnYourData/did-cmd/main/LICENSE)
