FROM ruby:2.5.9-alpine
MAINTAINER "Christoph Fabianek" christoph@ownyourdata.eu

RUN addgroup -S oydidgroup && \
	adduser -S oydid -G oydidgroup && \
    apk add --no-cache libsodium-dev git make gcc musl-dev jq && \
    gem install securerandom httparty ed25519 multibases multihashes optparse rbnacl dag uri && \
    apk del make gcc musl-dev && \
    wget https://raw.githubusercontent.com/OwnYourData/did-cmd/main/oydid.rb -O /usr/local/bin/oydid && \
    chmod 755 /usr/local/bin/oydid
USER oydid
WORKDIR /home/oydid

CMD ["sh"]