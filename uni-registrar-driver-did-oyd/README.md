# Universal Registrar Driver: `did:oyd`

This is a [Universal Registrar](https://github.com/decentralized-identity/universal-registrar/) driver for **did:oyd** identifiers.

## Specifications

* [Decentralized Identifiers](https://w3c.github.io/did-core/)
* [OYDID Method Specification](https://ownyourdata.github.io/oydid/)


## Build and Run (Docker)

```
docker build -f ./docker/Dockerfile . -t oydeu/oydid-registrar
docker run -p 8080:3000 oydeu/oydid-registrar
```


## OYDID Universal Registrar Driver

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
