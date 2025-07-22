#!/bin/bash
set -e

# Rollback script
PREVIOUS_TAG=$1

if [ -z "$PREVIOUS_TAG" ]; then
    echo "Usage: ./rollback.sh <previous-tag>"
    echo "Available tags:"
    docker images clockwork-backend --format "table {{.Tag}}"
    exit 1
fi

echo "Rolling back to version: $PREVIOUS_TAG"

# Stop current deployment
docker-compose -f docker-compose.production.yml down

# Start previous version
docker-compose -f docker-compose.production.yml up -d clockwork-backend:$PREVIOUS_TAG

echo "Rollback complete!"