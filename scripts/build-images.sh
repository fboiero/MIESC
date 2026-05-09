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

VERSION="5.4.1"
REGISTRY="ghcr.io/fboiero"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Source platform detection library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
source "$SCRIPT_DIR/detect-platform.sh"

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
        -f "$PROJECT_DIR/docker/Dockerfile" \
        -t miesc:${VERSION} \
        -t miesc:latest \
        -t ${REGISTRY}/miesc:${VERSION} \
        -t ${REGISTRY}/miesc:latest \
        "$PROJECT_DIR"

    echo -e "${GREEN}✓ Standard image built successfully${NC}"
    echo ""
}

build_full() {
    echo -e "${YELLOW}[2/2] Building FULL image (miesc:${VERSION}-full)...${NC}"
    echo "     Contains: ALL tools including Mythril, Manticore, Echidna, PyTorch"
    echo "     Size: ~8GB"
    echo "     Build time: 30-45 minutes"
    echo ""

    # ARM warning and confirmation
    if [ "$MIESC_IS_ARM" = true ]; then
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║  WARNING: Building full image on ARM (${MIESC_HOST_ARCH})              ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo "  Native ARM full builds skip Echidna, Medusa, Mythril, Manticore, Halmos, and Semgrep by default"
        echo "  because upstream releases are amd64-only, require long z3 source builds,"
        echo "  or ship ARM wheels that are not reliable in Docker."
        echo "  To force them on ARM, pass MIESC_BUILD_MYTHRIL=true,"
        echo "  MIESC_BUILD_MANTICORE=true, MIESC_BUILD_HALMOS=true, and/or"
        echo "  MIESC_BUILD_SEMGREP=true as build args."
        echo ""
        echo "  Alternatives:"
        echo "    - Pull the pre-built amd64 image (runs under QEMU, ~3-5x slower):"
        echo "      docker pull --platform linux/amd64 ${REGISTRY}/miesc:full"
        echo "    - Use the standard image (natively multi-arch, no Mythril/Manticore):"
        echo "      docker pull ${REGISTRY}/miesc:latest"
        echo ""
        read -p "Continue with native ARM build? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Skipping full image build.${NC}"
            return 0
        fi
    fi

    # Support explicit platform override via MIESC_FULL_PLATFORM
    local platform_flag=()
    if [ -n "${MIESC_FULL_PLATFORM:-}" ]; then
        platform_flag=(--platform "$MIESC_FULL_PLATFORM")
        echo -e "${BLUE}Using explicit platform: ${MIESC_FULL_PLATFORM}${NC}"
    fi

    docker build \
        "${platform_flag[@]}" \
        --build-arg MIESC_BASE_IMAGE=miesc:${VERSION} \
        --build-arg MIESC_BUILD_MYTHRIL="${MIESC_BUILD_MYTHRIL:-auto}" \
        --build-arg MIESC_BUILD_MANTICORE="${MIESC_BUILD_MANTICORE:-auto}" \
        --build-arg MIESC_BUILD_HALMOS="${MIESC_BUILD_HALMOS:-auto}" \
        --build-arg MIESC_BUILD_SEMGREP="${MIESC_BUILD_SEMGREP:-auto}" \
        -f "$PROJECT_DIR/docker/Dockerfile.full" \
        -t miesc:${VERSION}-full \
        -t miesc:full \
        -t ${REGISTRY}/miesc:${VERSION}-full \
        -t ${REGISTRY}/miesc:full \
        "$PROJECT_DIR"

    echo -e "${GREEN}✓ Full image built successfully${NC}"
    echo ""
}

push_images() {
    echo -e "${YELLOW}Pushing images to ${REGISTRY}...${NC}"

    # Standard images
    docker push ${REGISTRY}/miesc:${VERSION}
    docker push ${REGISTRY}/miesc:latest

    # Full images - warn on ARM native builds
    if [ "$MIESC_IS_ARM" = true ] && [ "${MIESC_FULL_PLATFORM:-}" != "linux/amd64" ]; then
        echo -e "${YELLOW}[WARN]${NC} Skipping push of full image: built natively for ${MIESC_HOST_ARCH}."
        echo "  The registry tag :full is expected to be amd64."
        echo "  To push an amd64 full image, rebuild with:"
        echo "    MIESC_FULL_PLATFORM=linux/amd64 ./scripts/build-images.sh push"
    else
        docker push ${REGISTRY}/miesc:${VERSION}-full
        docker push ${REGISTRY}/miesc:full
    fi

    echo -e "${GREEN}✓ Images pushed to registry${NC}"
}

show_summary() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                   BUILD COMPLETE                        ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Architecture info
    echo -e "${BOLD}Architecture:${NC}"
    echo "  Host: $(uname -m) (${MIESC_HOST_ARCH})"
    echo "  Docker platform: ${MIESC_DOCKER_PLATFORM}"
    if [ "$MIESC_IS_ARM" = true ]; then
        echo -e "  ${YELLOW}Note:${NC} The :full registry image is amd64-only."
        echo "  Local builds on ARM produce native arm64 images."
    fi
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
