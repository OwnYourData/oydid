# Universal Registrar Driver: `did:oyd`

This is a [Universal Registrar](https://github.com/decentralized-identity/universal-registrar/) driver for **did:oyd** identifiers.

The Universal Registrar creates/updates/deactivates Decentralized Identifiers (DIDs) across many different DID methods, based on the [W3C DID Core 1.0](https://www.w3.org/TR/did-core/) and [DID Registration](https://identity.foundation/did-registration/) specifications. See https://uniregistrar.io/ for a publicly hosted instance of a Universal Registrar.

## Specifications

* [Decentralized Identifiers](https://w3c.github.io/did-core/)    
* [OYDID Method Specification](https://ownyourdata.github.io/oydid/)    
* [Swagger API definition for Universal Registrar](https://github.com/decentralized-identity/universal-registrar/blob/main/swagger/api-driver.yml)


## Build and Run (Docker)

```
docker build -f ./docker/Dockerfile . -t oydeu/oydid-registrar
docker run -p 8080:3000 oydeu/oydid-registrar
```

### Verify with automated tests    

Use the following command to run the automated tests (including oydid-registrar tests) in the [`oydeu/oydid-cli`](https://hub.docker.com/r/oydeu/oydid-cli) Docker image:    

```bash
docker run -it --rm -w /usr/src/pytest oydeu/oydid-cli pytest
```


## Improve the OYDID Universal Registrar Driver

Please report bugs and suggestions for new features using the [GitHub Issue-Tracker](https://github.com/OwnYourData/oydid/issues) and follow the [Contributor Guidelines](https://github.com/twbs/ratchet/blob/master/CONTRIBUTING.md). Automated tests are available via [`pytest`](https://pypi.org/project/pytest/) - check out [test_general.py](https://github.com/OwnYourData/oydid/blob/main/cli/pytest/test_general.py).    

If you want to contribute, please follow these steps:

1. Fork it!
2. Create a feature branch: `git checkout -b my-new-feature`
3. Make sure all functionality is covered in [test_general.py](https://github.com/OwnYourData/oydid/blob/main/cli/pytest/test_general.py)
4. Commit changes: `git commit -am 'Add some feature'`
5. Push into branch: `git push origin my-new-feature`
6. Send a Pull Request

&nbsp;    

## License

[MIT License 2022 - OwnYourData.eu](https://raw.githubusercontent.com/OwnYourData/oydid/main/LICENSE)
