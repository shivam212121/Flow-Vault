#!/bin/sh

# Exit immediately if a command exits with a non-zero status.
set -e

# Check the RENDER_SERVICE_TYPE environment variable
if [ "$RENDER_SERVICE_TYPE" = "api" ]; then
  echo "Starting FastAPI API service..."
  exec uvicorn main:app --host 0.0.0.0 --port "$PORT"
elif [ "$RENDER_SERVICE_TYPE" = "worker" ]; then
  echo "Starting Celery worker service..."
  exec celery -A tasks.celery_app worker -l info
else
  echo "Error: RENDER_SERVICE_TYPE environment variable not set or invalid."
  echo "Set RENDER_SERVICE_TYPE to 'api' or 'worker'."
  exit 1
fi

