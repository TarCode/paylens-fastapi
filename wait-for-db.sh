#!/bin/sh
set -e

host="$1"
port="$2"
shift 2  # Remove the first two arguments (host and port)

until nc -z "$host" "$port"; do
  echo "Waiting for $host:$port..."
  sleep 1
done

echo "Database is ready! Executing command: $@"
exec "$@"