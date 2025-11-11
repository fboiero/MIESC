#!/bin/bash
# MIESC v3.3.0 - Docker Build Script
# Builds the MIESC Docker image with all dependencies

set -e  # Exit on error

echo "======================================"
echo "MIESC v3.3.0 - Docker Build"
echo "======================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="miesc"
IMAGE_TAG="3.3.0"
LATEST_TAG="latest"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed or not in PATH${NC}"
    echo "Please install Docker from https://www.docker.com/get-started"
    exit 1
fi

# Check if Docker daemon is running
if ! docker info &> /dev/null; then
    echo -e "${RED}Error: Docker daemon is not running${NC}"
    echo "Please start Docker and try again"
    exit 1
fi

echo -e "${BLUE}Building MIESC Docker image...${NC}"
echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""

# Build with BuildKit for better caching
export DOCKER_BUILDKIT=1

# Build the image
docker build \
    --tag "${IMAGE_NAME}:${IMAGE_TAG}" \
    --tag "${IMAGE_NAME}:${LATEST_TAG}" \
    --build-arg BUILDKIT_INLINE_CACHE=1 \
    --progress=plain \
    . 2>&1 | tee /tmp/docker_build_v3.log

# Check build status
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✅ Build successful!${NC}"
    echo ""
    echo "Image details:"
    docker images "${IMAGE_NAME}:${IMAGE_TAG}"
    echo ""
    echo -e "${GREEN}Next steps:${NC}"
    echo "  1. Run tests:       ./docker-run.sh test"
    echo "  2. Start API:       ./docker-run.sh api"
    echo "  3. Interactive:     ./docker-run.sh shell"
    echo "  4. Using compose:   docker-compose up --build"
    echo ""
else
    echo ""
    echo -e "${RED}❌ Build failed!${NC}"
    echo "Check /tmp/docker_build_v3.log for details"
    exit 1
fi
