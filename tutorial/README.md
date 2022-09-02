# OYDID Tutorial

*latest update: 2 September 2022*

This tutorial introduces the use of `did:oyd` DIDs with the following sections:

1) **[Deployment:](#deployment)** various options to run a DID repository locally, with a PostgreSQL DB backend, or on a Kubernetes cluster    
	a) [Local Deployment](#local-deployment)    
	b) [PostgreSQL Backend](#persisting-dids-in-postgresql)    
	c) [Kubernetes Cluster](#run-an-oydid-repository-on-a-kubernetes-cluster)    
2) **[DID Life-cycle:](#did-life-cycle)** describes the typical life-cycle of a DID using concrete and simple examples of entities exchanging information


## Deployment

### Local Deployment

If you just want to try OYDID locally, start a Docker container with the following command:
```console
docker run -d --name did_repo -e DID_DB=local -p 3000:3000 oydeu/oydid-base
```

Check if the repository is up and running by showing the *Repository Status* page at http://localhost:3000

You can create a new DID with the following `curl` statement (using the Uniregistrar API endpoint):
```console
echo '{"didDocument": {"test": "my first DID"}, 
       "options": {"location":"http://localhost:3000"}}' | \
curl -H "Content-Type: application/json" -d @- -X POST http://localhost:3000/1.0/create
```

As a result you will see a JSON document that starts with:
```json
{
  "didState":{
    "did":"did:oyd:zQmXaUXEZBYXkNgYd4WEzisw1RGfsCyAVk91QssvsVc4jwM%40http://localhost:3000",
    "state":"finished" 
    ...
```

Resolve the DID to get the original DID document (using the Uniresolver API endpoint and replacing the DID with the response from above):
```console
curl http://localhost:3000/1.0/identifiers/did%3Aoyd%3AzQmXaUXEZBYXkNgYd4WEzisw1RGfsCyAVk91QssvsVc4jwM%40http%3A%2F%2Flocalhost%3A3000
```

Clean up your environment by removing the Docker container:
```console
docker rm -f did_repo
```
***Important note:*** As soon as you end the `did_repo` container all DIDs and associated information are lost since it is stored in a Sqlite3 database inside the container.

[back to top](#)

### Persisting DIDs in PostgreSQL

For a more serious evaluation of OYDID you might want to persist DIDs, associated DID Documents, and accompanying DID Logs in a database outside the DID Repository. The following `docker-compose.yml` provides an example for such a setup with a persistent volume for the PostgreSQL data directory:

```yaml
version: "3"
services:
  oydid:
    image: oydeu/oydid-base:latest
    environment:
      DID_DB: "external"
      RAILS_ENV: "production"
    ports:
      - "3000:3000"
    depends_on:
      - "db"
  db:
    image: postgres:12.1
    environment:
      POSTGRES_HOST_AUTH_METHOD: "trust"
    volumes:
      - oydid_data:/var/lib/postgresql/data
volumes:
  oydid_data:
```

Start with:
```console
docker-compose -f docker-compose.yml up -d
```

The status page is again available at http://localhost:3000 and you can use the `oydeu/oydid-cli` instead of curl commands to interact with the repo - use the following command to start the CLI:
```console
docker run -it --rm --network host oydeu/oydid-cli
```

Create a new DID: 
```console
echo '{"my":"test"}' | oydid create -l http://localhost:3000
```
Output:
`created did:oyd:zQmUogZxErEgXgzEMv9zXK9qnBBYzZfiHvQ4FJiXhZsdFqH%40http%3A%2F%2Flocalhost:3000`


Resolve the DID:
```console
oydid read did:oyd:zQmUogZxErEgXgzEMv9zXK9qnBBYzZfiHvQ4FJiXhZsdFqH%40http%3A%2F%2Flocalhost:3000
```

and show the DID in the W3C-conform representation:
```console
oydid read --w3c-did did:oyd:zQmUogZxErEgXgzEMv9zXK9qnBBYzZfiHvQ4FJiXhZsdFqH%40http%3A%2F%2Flocalhost:3000 | jq
```

with the output:
```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:oyd:zQmSkd6VwTDGFnLtxg6uaqjSAan8JJCAkFYWDnHLXKPethi@http://localhost:3000",
  "verificationMethod": [
    {
      "id": "did:oyd:zQmSkd6VwTDGFnLtxg6uaqjSAan8JJCAkFYWDnHLXKPethi@http://localhost:3000#key-doc",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:oyd:zQmSkd6VwTDGFnLtxg6uaqjSAan8JJCAkFYWDnHLXKPethi@http://localhost:3000",
      "publicKeyMultibase": "z6MuxmgB9AzyQNpDLVVs9C911zrtDGEetXaS4DfDiFMMpxFQ"
    },
    {
      "id": "did:oyd:zQmSkd6VwTDGFnLtxg6uaqjSAan8JJCAkFYWDnHLXKPethi@http://localhost:3000#key-rev",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:oyd:zQmSkd6VwTDGFnLtxg6uaqjSAan8JJCAkFYWDnHLXKPethi@http://localhost:3000",
      "publicKeyMultibase": "z6Muxj69maMeBaKYw9jPUFLDTVWe7eRPuegdZxYyyAnxcydX"
    }
  ],
  "service": {
    "my": "test"
  }
}
```

To clean up the environment close the OYDID CLI (just type `exit` on the command line) and stop the containers:
```console
docker-compose -f docker-compose.yml down
```

[back to top](#)

### Run an OYDID Repository on a Kubernetes Cluster

The production site for the [default OYDID repository](https://oydid.ownyourdata.eu) (at https://oydid.ownyourdata.eu) is hosted on a Kubernetes cluster with a dedicated PostreSQL cluster. The follwing files were used as setup on this Kubernetes cluster (currently at v1.91.2):
* [deplyoment.yaml](res/deployment.yaml)    
* [service.yaml](res/service.yaml)
* [ingress.yaml](res/ingress.yaml)
* [cert.yaml](res/cert.yaml)
* [secrets.yaml](res/secrets.yaml)

If you have any questions about setting up an OYDID repository on Kubernetes don't hesitate to [contact us](mailto:support@ownyourdata.eu)!

[back to top](#)

## DID Life-cycle

This section describes the typical life-cycle of a DID using concrete and simple examples of entities exchanging information and parties trying to interfere or manipulate this exchange. The following actors and roles are used:    
* Alice (A) wants to share information using OYDID    
* Bob (B) receives information and validates the sender    
* Dave (D) is trusted by Alice (A) and acts as a delegate for her    
* Eve (E) is a malicious party and tries to manipulate the information exchange unnoticed    

Each step describes a task performed by one of the actors and provides commands (to be run on a command line like bash) demonstrating working with OYDID.

### Prerequisites

To execute commands in the steps below make sure to have the following tools installed:    
* `oydid`: download and installation instructions [available here](https://github.com/OwnYourData/oydid/tree/main/cli)    
* `jq`: download and installation instructions [available here](https://stedolan.github.io/jq/download/)    

Alternatively, you can use a ready-to-use Docker image with all tools pre-installed: [https://hub.docker.com/r/oydeu/oydid-base](https://hub.docker.com/r/oydeu/oydid-base). Use the following command to start the image:    

```console
docker run -it --rm --network host -v ~/.oydid:/home/oydid oydeu/oydid-cli
```

*Note:* since it makes sense to keep private keys and revocation information beyond a Docker session a directory is mounted in the container to persist files; create a local directory, `mkdir ~/.oydid`


### Alice creates a DID to document an available service endpoint

Alice provides a service endpoint and wants to share this information in a DID document.

run the following command:    
```console
echo '{"service":"https://business.data-container.net/api/data"}' | oydid create
```


### Bob resolves the DID

Bob receives the DID (e.g., `did:oyd:123aBz`) and wants to resolve the linked DID document to get access to the service endpoint provided by Alice.

run the following command:    
```console
oydid read 123aBz
```


### Alice updates the DID Document

Alice moves her data to another service and wants to update the service endpoint in the DID document.

run the following command:    
```console
echo '{"service":"https://biz2.data-container.net/api/data"}' | oydid update 123aBz
```


### Bob clones Alice's DID Document

Bob has a stake in the DID document published by Alice and therefore, wants to maintain a separate copy of the DID in case Alice's hosting is not available.

run the following command:    
```console
oydid clone 456aBz -l https://did2.data-container.net
```


### Alice deactivates the DID

Alice wants to publish the information that the previously released DID document is not valid anymore.

run the following command:    
```console
oydid revoke 456aBz
```

[back to top](#)

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
