FROM ruby:2.3
RUN sed -i s/deb.debian.org/archive.debian.org/g /etc/apt/sources.list
RUN sed -i s/security.debian.org/archive.debian.org/g /etc/apt/sources.list
RUN sed -i s/stretch-updates/stretch/g /etc/apt/sources.list
RUN apt-get update -qq 
# RUN apt-get upgrade
RUN apt-get install -y nodejs postgresql-client
WORKDIR /usr/src/app
COPY Gemfile .
COPY Gemfile.lock .
ENV BUNDLE_FROZEN=true
RUN bundle install
COPY . .


ENV RAILS_SERVE_STATIC_FILES=true

# Redirect Rails log to STDOUT for Cloud Run to capture
ENV RAILS_LOG_TO_STDOUT=true

# Add a script to be executed every time the container starts. Fixes a glitch with the pids directory by removing the server.pid file on execute.
RUN chmod +x /usr/src/app/entrypoint.sh
ENTRYPOINT ["/usr/src/app/entrypoint.sh"]