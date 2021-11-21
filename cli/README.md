# OYDID Command Line Tool

OYDID (Own Your Digital IDentifier) provides a self-sustained environment for managing digital identifiers (DIDs). The oyd:did method links the identifier cryptographically to the DID Document and through also cryptographically linked provenance information in a public log it ensures resolving to the latest valid version of the DID Document.

## Installation
Run the following command to copy `oydid.rb` into `~/bin/oydid` (requires Ruby 2.5.7 or higher):
```bash
sh -c "curl -fsSL https://raw.githubusercontent.com/OwnYourData/did-cmd/main/install.sh | sh"
```

## Run via Docker
To use the dockerized version of oydid run:
```bash
docker run -it --rm oydeu/oydid
```

Often it makes sense to keep private keys and revocation information beyond a Docker session:

* create a local directory, e.g., `mkdir ~/.oydid`
* mount this directory on startup: `docker run -it --rm -v ~/.oydid:/home/oydid oydeu/oydid`


## Example
create the most simple DID:
```bash
echo '{"hello":"world"}' | oydid create
```

read the information:
```bash
oydid read {use output from above did:oyd:...}
```

## Further Resources
Read about the concept and examples: [OYDIDintro.pdf](https://github.com/OwnYourData/did-cmd/blob/main/docs/OYDIDintro.pdf)    
W3C conform DID Method Specification: https://github.com/OwnYourData/did-cmd/blob/main/docs/did-spec.md    
`oydid` commandline tool in a Docker image: https://hub.docker.com/repository/docker/oydeu/oydid     
To host DIDs yourself you can use the `oydid/did-base` image on Dockerhub: https://hub.docker.com/r/oydid/did-base    
API documentation is available here: https://api-docs.ownyourdata.eu/oydid/    
Universal Resolver driver: https://github.com/OwnYourData/did-cmd/tree/main/resolver    


&nbsp;    

## OYDID Command Line Tool

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
