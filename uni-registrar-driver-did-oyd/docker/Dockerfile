FROM ruby:2.5.9
MAINTAINER "Christoph Fabianek" christoph@ownyourdata.eu

WORKDIR /usr/src/app
ENV RAILS_ROOT $WORKDIR
RUN mkdir -p $RAILS_ROOT/tmp/pids && \
	apt-get update && \
	apt-get install -y --no-install-recommends \
  		libsodium-dev \
		build-essential && \
	rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY Gemfile $WORKDIR
RUN gem install bundler:1.17.3 && \
	gem update --system 3.2.3 && \
	bundle install && \
	bundle update

ENV LANG=C.UTF-8
ENV RAILS_LOG_TO_STDOUT="TRUE"
ENV RAILS_ENV=production

COPY . .

RUN gem update bundler && \
	bundle update

CMD ["rails", "server", "-b", "0.0.0.0"]

EXPOSE 3000
