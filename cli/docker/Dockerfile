FROM ruby:2.5.9-alpine
MAINTAINER "Christoph Fabianek" christoph@ownyourdata.eu

RUN addgroup -S user && \
    adduser -S user -G user && \
    apk add --no-cache libsodium-dev git make gcc musl-dev jq && \
    gem install securerandom httparty ed25519 multibases multihashes optparse rbnacl dag uri && \
    apk del make gcc musl-dev && \
    wget https://raw.githubusercontent.com/OwnYourData/oydid/main/cli/oydid.rb -O /usr/local/bin/oydid && \
    chmod 755 /usr/local/bin/oydid && \
    sed -e "s/\${oydid}/`oydid --version`/" -e "s/\${jq}/`jq --version`/" docker/welcome.txt > /etc/motd
USER user
WORKDIR /home/user
COPY docker/home .

CMD ["bash"]