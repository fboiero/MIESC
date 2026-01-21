#!/bin/bash
# MIESC Docker Image Builder
# Builds both standard and full images
#
# Usage:
#   ./scripts/build-images.sh          # Build both images
#   ./scripts/build-images.sh standard # Build standard image only
#   ./scripts/build-images.sh full     # Build full image only
#   ./scripts/build-images.sh push     # Build and push to ghcr.io

set -e

VERSION="4.3.7"
REGISTRY="ghcr.io/fboiero"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     MIESC v${VERSION} - Docker Image Builder           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

build_standard() {
    echo -e "${YELLOW}[1/2] Building STANDARD image (miesc:${VERSION})...${NC}"
    echo "     Contains: Slither, Aderyn, Solhint, Foundry"
    echo "     Size: ~2-3GB"
    echo ""

    docker build \
        -f Dockerfile \
        -t miesc:${VERSION} \
        -t miesc:latest \
        -t ${REGISTRY}/miesc:${VERSION} \
        -t ${REGISTRY}/miesc:latest \
        .

    echo -e "${GREEN}✓ Standard image built successfully${NC}"
    echo ""
}

build_full() {
    echo -e "${YELLOW}[2/2] Building FULL image (miesc:${VERSION}-full)...${NC}"
    echo "     Contains: ALL tools including Mythril, Manticore, Echidna, PyTorch"
    echo "     Size: ~8GB"
    echo "     Build time: 30-45 minutes"
    echo ""

    docker build \
        -f Dockerfile.full \
        -t miesc:${VERSION}-full \
        -t miesc:full \
        -t ${REGISTRY}/miesc:${VERSION}-full \
        -t ${REGISTRY}/miesc:full \
        .

    echo -e "${GREEN}✓ Full image built successfully${NC}"
    echo ""
}

push_images() {
    echo -e "${YELLOW}Pushing images to ${REGISTRY}...${NC}"

    # Standard images
    docker push ${REGISTRY}/miesc:${VERSION}
    docker push ${REGISTRY}/miesc:latest

    # Full images
    docker push ${REGISTRY}/miesc:${VERSION}-full
    docker push ${REGISTRY}/miesc:full

    echo -e "${GREEN}✓ All images pushed to registry${NC}"
}

show_summary() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                   BUILD COMPLETE                        ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Available images:"
    echo ""
    echo -e "  ${BLUE}STANDARD${NC} (lightweight, ~2-3GB):"
    echo "    - miesc:${VERSION}"
    echo "    - miesc:latest"
    echo "    - ${REGISTRY}/miesc:${VERSION}"
    echo ""
    echo -e "  ${BLUE}FULL${NC} (all tools, ~8GB):"
    echo "    - miesc:${VERSION}-full"
    echo "    - miesc:full"
    echo "    - ${REGISTRY}/miesc:${VERSION}-full"
    echo ""
    echo "Usage:"
    echo "  # Standard image"
    echo "  docker run -it --rm miesc:${VERSION} --help"
    echo ""
    echo "  # Full image (all tools)"
    echo "  docker run -it --rm miesc:${VERSION}-full --help"
    echo ""
    echo "  # Check available tools"
    echo "  docker run -it --rm miesc:${VERSION}-full doctor"
    echo ""
}

# Main logic
case "${1:-all}" in
    standard)
        build_standard
        ;;
    full)
        build_full
        ;;
    push)
        build_standard
        build_full
        push_images
        ;;
    all|*)
        build_standard
        build_full
        ;;
esac

show_summary
