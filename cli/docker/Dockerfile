FROM ruby:3.2.8-alpine
LABEL org.opencontainers.image.authors="Christoph Fabianek <christoph@ownyourdata.eu>"

# NOTE: oydid.gemspec sets required_ruby_version >= 3.2.8 - an older base image
# cannot install the gem at all. Keep in sync with docker/Dockerfile-local; the
# only difference is that this file installs oydid from rubygems.org instead of
# docker/local-gem/.
RUN addgroup -S user && \
    adduser -S user -G user && \
    apk add --no-cache libsodium-dev openssl openssl-dev git make gcc musl-dev jq bash curl gdbm gdbm-dev enscript ghostscript && \
    gem install httparty ed25519 multibases multihashes multicodecs optparse rbnacl dag uri json-canonicalization oydid securerandom && \
    gem install openssl -v "~> 3.3.2" && \
    apk add --update --no-cache python3 py3-pip pipx py3-setuptools py3-pytest py3-requests && \
    ln -sf python3 /usr/bin/python && \
    pip install --no-cache-dir --break-system-packages pytest-subprocess pyserial
COPY oydid.rb /usr/local/bin/oydid
COPY ./docker/start.sh /usr/local/bin/start.sh
COPY --chown=user:user ./docker ./docker
COPY docker/welcome.txt /tmp/welcome.txt
COPY docker/etc/profile /etc/profile
RUN chmod 755 /usr/local/bin/oydid && \
    sed -e "s/\${oydid}/`oydid --version | head -n 1`/" -e "s/\${jq}/`jq --version`/" /tmp/welcome.txt > /etc/motd && \
    mkdir -p /usr/src/pytest
COPY --chown=user:user pytest /usr/src/pytest
COPY Rakefile /usr/src/pytest

USER user
WORKDIR /home/user

CMD ["/usr/local/bin/start.sh"]
