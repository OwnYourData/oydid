#!/bin/bash

case "$DID_DB" in
		local)
			cp config/database_sqlite3.yml config/database.yml
			;;
		external)
			cp config/database_pg.yml config/database.yml
			;;
		*)
			cp config/database_k8s.yml config/database.yml
			;;
esac


rm -f /usr/src/app/tmp/pids/server.pid /usr/src/app/log/*.log
bundle exec rake db:migrate

rails server -b 0.0.0.0 &
sleep infinity