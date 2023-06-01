# Own Your Decentralized IDentifier (OYDID)

OYDID provides a self-sustained environment for managing decentralised identifiers (DIDs). The `did:oyd` method links the identifier cryptographically to the DID Document and through also cryptographically linked provenance information in a public log it ensures resolving to the latest valid version of the DID Document.

## Resources
* Read about the concept and examples: [OYDIDintro.pdf](https://github.com/OwnYourData/oydid/raw/main/docs/OYDIDintro.pdf)    
* W3C conform DID Method Specification: https://ownyourdata.github.io/oydid/    
* `oydid` commandline tool:    
    * Sources: https://github.com/OwnYourData/oydid/tree/main/cli    
    * run in a Docker image: https://hub.docker.com/r/oydeu/oydid-cli     
    * Tutorial and examples: https://github.com/OwnYourData/oydid/tree/main/tutorial
* host OYDIDs yourself in a repository:    
    * Sources: https://github.com/OwnYourData/oydid/tree/main/repository    
    * use the `oydeu/oydid-base` image on Dockerhub: https://hub.docker.com/r/oydeu/oydid-base    
    * API documentation is available here: https://api-docs.ownyourdata.eu/oydid/    
* Universal Resolver driver: https://github.com/OwnYourData/oydid/tree/main/uniresolver-plugin    
* Universal Registrar driver : https://github.com/OwnYourData/oydid/tree/main/uni-registrar-driver-did-oyd    
* JS library for [`did-resolver`](https://github.com/decentralized-identity/did-resolver): https://github.com/OwnYourData/oydid/tree/main/js-resolver     

&nbsp;    

## OYDID Issues

Please report bugs and suggestions for new features using the [GitHub Issue-Tracker](https://github.com/OwnYourData/oydid/issues) and follow the [Contributor Guidelines](https://github.com/twbs/ratchet/blob/master/CONTRIBUTING.md).

If you want to contribute, please follow these steps:

1. Fork it!
2. Create a feature branch: `git checkout -b my-new-feature`
3. Commit changes: `git commit -am 'Add some feature'`
4. Push into branch: `git push origin my-new-feature`
5. Send a Pull Request

&nbsp;    

## About  

<img align="right" src="https://raw.githubusercontent.com/OwnYourData/soya/main/res/logo-ngi-ontochain-positive.png" height="150">This project has received funding from the European Union’s Horizon 2020 research and innovation program through the [NGI ONTOCHAIN program](https://ontochain.ngi.eu/) under cascade funding agreement No 957338.<br>Also supported by the Federal Ministry for Climate Protection, Environment, Energy, Mobility, Innovation and Technology (Bundesministerium für Klimaschutz, Umwelt, Energie, Mobilität, Innovation und Technologie [BMK]) through FFG funding in the program “IKT der Zukunft” under [grant number 887052](https://projekte.ffg.at/projekt/4125456).


<img align="left" src="https://raw.githubusercontent.com/OwnYourData/oydid/main/res/210614_FFG-BM-Logoleisten_CMYK_01_BMDW-BMK-FFG_128mm.jpg" height="150">

<br clear="both" />

## License

[MIT License 2022 - OwnYourData.eu](https://raw.githubusercontent.com/OwnYourData/oydid/main/LICENSE)
