FROM ruby:2.5.9-alpine
MAINTAINER "Christoph Fabianek" christoph@ownyourdata.eu

RUN addgroup -S user && \
    adduser -S user -G user && \
    apk add --no-cache libsodium-dev git make gcc musl-dev jq bash curl && \
    gem install httparty ed25519 multibases multihashes multicodecs optparse rbnacl dag uri oydid && \
    gem install json-canonicalization -v 0.2.1 && \
    gem install securerandom -v 0.1.1 && \
    apk del make gcc musl-dev && \
    apk add --update --no-cache python3 && ln -sf python3 /usr/bin/python && \
    python3 -m ensurepip && \
    pip3 install --no-cache --upgrade pip setuptools pytest requests pytest-subprocess
COPY oydid.rb /usr/local/bin/oydid
COPY docker/welcome.txt /tmp/welcome.txt
RUN chmod 755 /usr/local/bin/oydid && \
    sed -e "s/\${oydid}/`oydid --version`/" -e "s/\${jq}/`jq --version`/" /tmp/welcome.txt > /etc/motd && \
    mkdir -p /usr/src/pytest
COPY --chown=user:user pytest /usr/src/pytest
USER user
WORKDIR /home/user
COPY docker/home .

CMD ["bash"]