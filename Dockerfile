FROM ruby:2.3

# ruby 2.3 compatibility workaround
RUN sed -i s/deb.debian.org/archive.debian.org/g /etc/apt/sources.list
RUN sed -i s/security.debian.org/archive.debian.org/g /etc/apt/sources.list
RUN sed -i s/stretch-updates/stretch/g /etc/apt/sources.list

RUN apt-get update -qq 
RUN apt-get install -y nodejs postgresql-client

WORKDIR /app

COPY Gemfile .
COPY Gemfile.lock .
ENV BUNDLE_FROZEN=true
RUN bundle install

COPY . .

# Redirect Rails log to STDOUT for Cloud Run to capture
ENV RAILS_LOG_TO_STDOUT=true

RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
