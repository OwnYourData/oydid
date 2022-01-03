# OYDID Tutorial

*latest update: 3 January 2022*

This tutorial introduces the use of `did:oyd` DIDs. It describes the typical life-cycle of a DID using concrete and simple examples of entities exchanging information and parties trying to interfere or manipulate this exchange. The following actors and roles are used:    
* Alice (A) wants to share information using OYDID    
* Bob (B) receives information and validates the sender    
* Dave (D) is trusted by Alice (A) and acts as a delegate for her    
* Eve (E) is a malicious party and tries to manipulate the information exchange unnoticed    

Each step describes a task performed by one of the actors and provides commands (to be run on a command line like bash) demonstrating working with OYDID.

## Prerequisites

To execute commands in the steps below make sure to have the following tools installed:    
* `oydid`: download and installation instructions [available here](https://github.com/OwnYourData/oydid/tree/main/cli)    
* `jq`: download and installation instructions [available here](https://stedolan.github.io/jq/download/)    

Alternatively, you can use a ready-to-use Docker image with all tools pre-installed: [https://hub.docker.com/r/oydeu/oydid-base](https://hub.docker.com/r/oydeu/oydid-base). Use the following command to start the image:    

```console
docker run -it --rm -v ~/.oydid:/home/oydid oydeu/oydid-cli
```

*Note:* since it makes sense to keep private keys and revocation information beyond a Docker session a directory is mounted in the container to persist files; create a local directory, `mkdir ~/.oydid`


## Alice creates a DID to document an available service endpoint

Alice provides a service endpoint and wants to share this information in a DID document.

run the following command:    
```console
echo '{"service":"https://business.data-container.net/api/data"}' | oydid create
```


&nbsp;    

## OYDID Tutorial

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
