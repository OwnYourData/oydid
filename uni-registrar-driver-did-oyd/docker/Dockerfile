FROM ruby:3.2.8
LABEL org.opencontainers.image.authors="Christoph Fabianek <christoph@ownyourdata.eu>"

WORKDIR /usr/src/app
ENV RAILS_ROOT=/usr/src/app/
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

ENV LANG=C.UTF-8
ENV RAILS_LOG_TO_STDOUT="TRUE"
ENV RAILS_ENV=production

COPY . .

CMD ["rails", "server", "-b", "0.0.0.0"]

EXPOSE 3000
