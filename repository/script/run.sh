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
bundle exec rake db:create

# A failed migration used to be ignored here: the task printed its error, the
# script carried on and Rails served requests against a schema the code does
# not match. oydid2 ran that way from 2022 until 2026-08-22, because one
# migration was missing from schema_migrations while its column already
# existed - every start hit the same error and nobody saw it.
#
# Refusing to start turns that into a CrashLoopBackOff, which is visible, and
# the rolling update keeps the previous pod serving in the meantime.
if ! bundle exec rake db:migrate; then
    echo "FATAL: db:migrate failed - refusing to start against a mismatched schema" >&2
    exit 1
fi
if [[ -z "${SECRET_KEY_BASE}" ]]; then
	export SECRET_KEY_BASE=`bundle exec rails secret`
fi

rails server -b 0.0.0.0 &
sleep infinity