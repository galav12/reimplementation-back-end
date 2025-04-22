ARG RUBY_VERSION=3.2.7
FROM ruby:$RUBY_VERSION

# Install dependencies
RUN apt-get update -qq && \
    apt-get install -y \
    build-essential \
    libvips \
    nodejs \
    npm \
    default-mysql-client \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

WORKDIR /app

# Install gems
COPY Gemfile Gemfile.lock ./
RUN gem install bundler && \
    bundle install --without development test

# Copy application
COPY . .

# Precompile assets
# RUN bundle exec rails assets:precompile

# Set production environment
ENV RAILS_ENV=development
ENV RAILS_LOG_TO_STDOUT="1" \
    RAILS_SERVE_STATIC_FILES="true"

EXPOSE 3002

# Add entrypoint for DB setup
COPY entrypoint.sh /usr/bin/
RUN chmod +x /usr/bin/entrypoint.sh
ENTRYPOINT ["entrypoint.sh"]
CMD ["rails", "server", "-b", "0.0.0.0", "-p", "3002"]