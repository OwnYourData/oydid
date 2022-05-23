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

[MIT License 2022 - OwnYourData.eu](https://raw.githubusercontent.com/OwnYourData/oydid/main/LICENSE)
