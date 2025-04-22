#!/bin/sh
set -e

# Wait for database to be ready
until mysql -h db -u dev -proot -e 'SELECT 1' >/dev/null 2>&1; do
  echo "Waiting for database connection..."
  sleep 2
done

# Run migrations
bundle exec rails db:migrate

exec "$@"