#!/usr/bin/env bash

cd /app

# Create the Rails production DB on first run
RAILS_ENV=production bundle exec rake db:create

# update database schema
RAILS_ENV=production bundle exec rake db:migrate

# Do some protective cleanup
# > log/production.log
# Fixes a glitch with the pids directory by removing the server.pid file on execute.
rm -f tmp/pids/server.pid

# Specify $PORT as an env variable through Cloud Run
bundle exec rails server -e production -b 0.0.0.0 -p $PORT
