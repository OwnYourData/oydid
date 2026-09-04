# OYDID Command Line Tool

OYDID (Own Your Digital IDentifier) provides a self-sustained environment for managing digital identifiers (DIDs). The oyd:did method links the identifier cryptographically to the DID Document and through also cryptographically linked provenance information in a public log it ensures resolving to the latest valid version of the DID Document.

## Installation
Run the following command to copy `oydid.rb` into `~/bin/oydid` (requires Ruby 2.5.7 or higher):
```bash
sh -c "curl -fsSL https://raw.githubusercontent.com/OwnYourData/oydid/main/cli/install.sh | sh"
```

## Run via Docker
To use the dockerized version of oydid run:
```bash
docker run -it --rm oydeu/oydid-cli
```

Often it makes sense to keep private keys and revocation information beyond a Docker session:

* create a local directory, e.g., `mkdir ~/.oydid`
* mount this directory on startup: `docker run -it --rm -v ~/.oydid:/home/oydid oydeu/oydid-cli`

## Build Docker image

To package oydid-cli with additional tools ([jq](https://stedolan.github.io/jq/)) in a ready-to-use Docker container run the following command in the `cli` directory:    
```bash
./build.sh
```

The current `oydeu/oydid-cli` Docker image is available here: https://hub.docker.com/r/oydeu/oydid-cli

### Verify with automated tests    

Use the following command to run the automated tests in the `oydeu/oydid-cli` Docker image:    

```bash
docker run -it --rm -w /usr/src/pytest -e OYDIDCMD=oydid oydeu/oydid-cli pytest
```

## Example
create the most simple DID:
```bash
echo '{"hello":"world"}' | oydid create
```

read the information:
```bash
oydid read {use output from above did:oyd:...}
```

## DIDComm signed messages

Signing needs a DID whose document lists the signing key for authentication, so
create it with `--authentication` (this becomes part of the DID Document and
therefore of the identifier - it cannot be added to an existing DID without
`oydid update`, which mints a new identifier):
```bash
echo '{"id":"my-service"}' | oydid create --authentication
```

Wrap a payload in a DIDComm message and sign it with the document key:
```bash
echo '{"my":"message"}' | \
  oydid message --type https://ownyourdata.eu/oydid/0.1/example --to $DID | \
  oydid jws --sign-did $DID > token.jws
```

Verify it. **Always pass `--expect-did`**: the verifier takes the public key from
the `kid` header of the token, so without it a successful verification only says
that whoever controls *the DID named in the token* signed it - not that it was
the DID you expected. `oydid` writes a warning to stderr when the option is
missing and exits non-zero when verification fails:
```bash
oydid verify-jws --expect-did $DID < token.jws
```

## Further Resources

Read about the concept and examples: [OYDIDintro.pdf](https://github.com/OwnYourData/oydid/blob/main/docs/OYDIDintro.pdf)    
W3C conform DID Method Specification: https://ownyourdata.github.io/oydid/    
`oydid` commandline tool in a Docker image: https://hub.docker.com/r/oydeu/oydid-cli         
To host DIDs yourself you can use the `oydeu/oydid-base` image on Dockerhub: https://hub.docker.com/r/oydeu/oydid-base    
API documentation is available here: https://api-docs.ownyourdata.eu/oydid/    
Universal Resolver driver: https://github.com/OwnYourData/oydid/tree/main/uniresolver-plugin    
JS library for `did-resolver`: https://github.com/OwnYourData/oydid/tree/main/js-resolver    



&nbsp;    

## OYDID Command Line Tool

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
