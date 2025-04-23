#!/bin/sh
set -e

# Function to check MySQL connectivity
check_mysql() {
  echo "Waiting for MySQL to be ready..."
  until mysql -h db -u dev -proot -e 'SELECT 1' >/dev/null 2>&1; do
    echo "MySQL is unavailable - sleeping"
    sleep 2
  done
  echo "MySQL is up and running"
}

# Function to check Redis connectivity
check_redis() {
  echo "Waiting for Redis to be ready..."
  until redis-cli -h redis ping | grep -q PONG; do
    echo "Redis is unavailable - sleeping"
    sleep 1
  done
  echo "Redis is up and running"
}

# Run both checks in parallel (timeout after 60 seconds)
timeout 60 bash -c 'check_mysql & check_redis & wait' || {
  echo "Error: Some services failed to start within timeout period"
  exit 1
}

# Run migrations
echo "Running database migrations..."
bundle exec rails db:migrate || {
  echo "Error: Database migrations failed"
  exit 1
}

# Execute the main container command
echo "Starting Rails server..."
exec "$@"