FROM ruby:3.2.8
LABEL org.opencontainers.image.authors="Christoph Fabianek <christoph@ownyourdata.eu>"

WORKDIR /usr/src/app
ENV RAILS_ROOT=/usr/src/app/
# multicodecs parses its codec table as CSV and raises CSV::InvalidEncodingError
# without a UTF-8 locale; production sets LANG via the k8s manifest, this makes
# a plain `docker run` work as well
ENV LANG=C.UTF-8
RUN mkdir -p $RAILS_ROOT/tmp/pids && \
	apt-get update && \
	apt-get install -y --no-install-recommends \
		libsodium-dev \
		build-essential && \
	rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Gemfile.lock is authoritative - it pins the oydid version this image runs.
# That version must be published on rubygems.org; for an unreleased gem use
# ./build.sh --local (Dockerfile-local) instead.
COPY Gemfile Gemfile.lock $RAILS_ROOT

RUN gem install bundler && \
	bundle install

COPY . .

CMD ["./script/run.sh"]

EXPOSE 3000
