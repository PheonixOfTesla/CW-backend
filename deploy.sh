#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}🚀 ClockWork Backend Deployment${NC}"

# Check environment
if [ "$1" != "production" ] && [ "$1" != "staging" ]; then
    echo -e "${RED}Usage: ./deploy.sh [production|staging]${NC}"
    exit 1
fi

ENVIRONMENT=$1
echo -e "${YELLOW}Deploying to: ${ENVIRONMENT}${NC}"

# Load environment variables
if [ -f ".env.${ENVIRONMENT}" ]; then
    export $(cat .env.${ENVIRONMENT} | sed 's/#.*//g' | xargs)
else
    echo -e "${RED}Error: .env.${ENVIRONMENT} file not found${NC}"
    exit 1
fi

# Pre-deployment checks
echo -e "${YELLOW}Running pre-deployment checks...${NC}"

# Check Node version
NODE_VERSION=$(node -v | cut -d'v' -f2)
REQUIRED_NODE="18.0.0"
if [ "$(printf '%s\n' "$REQUIRED_NODE" "$NODE_VERSION" | sort -V | head -n1)" != "$REQUIRED_NODE" ]; then
    echo -e "${RED}Error: Node.js version must be >= 18.0.0${NC}"
    exit 1
fi

# Run tests
echo -e "${YELLOW}Running tests...${NC}"
npm test

# Build Docker image
echo -e "${YELLOW}Building Docker image...${NC}"
docker build -f Dockerfile.production -t clockwork-backend:latest .

# Tag image
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
docker tag clockwork-backend:latest clockwork-backend:${TIMESTAMP}

# Database migrations
echo -e "${YELLOW}Running database migrations...${NC}"
npm run migrate:production

# Stop old containers
echo -e "${YELLOW}Stopping old containers...${NC}"
docker-compose -f docker-compose.${ENVIRONMENT}.yml down

# Start new containers
echo -e "${YELLOW}Starting new containers...${NC}"
docker-compose -f docker-compose.${ENVIRONMENT}.yml up -d

# Wait for health checks
echo -e "${YELLOW}Waiting for services to be healthy...${NC}"
sleep 10

# Verify deployment
HEALTH_CHECK=$(curl -s http://localhost:3001/health | jq -r '.status')
if [ "$HEALTH_CHECK" = "healthy" ]; then
    echo -e "${GREEN}✅ Deployment successful!${NC}"
else
    echo -e "${RED}❌ Deployment failed - health check failed${NC}"
    docker-compose -f docker-compose.${ENVIRONMENT}.yml logs
    exit 1
fi

# Clean up old images
echo -e "${YELLOW}Cleaning up old images...${NC}"
docker image prune -a -f --filter "until=24h"

echo -e "${GREEN}🎉 Deployment complete!${NC}"