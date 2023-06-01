FROM ruby:2.6.9
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

RUN bundle install

COPY . .

RUN gem update bundler && \
	gem install bundler:1.17.3 && \
	gem update --system 3.2.3 && \
	bundle install && \
	bundle update && \
	gem cleanup

CMD ["./script/run.sh"]

EXPOSE 3000
