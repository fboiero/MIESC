#!/bin/bash
# MIESC Platform Detection Library
# Detects host architecture and provides platform-aware helpers
# for Docker image selection (amd64 vs arm64).
#
# Usage (source from other scripts):
#   source "$SCRIPT_DIR/detect-platform.sh"
#   echo "$MIESC_HOST_ARCH"          # e.g. amd64, arm64
#   echo "$MIESC_DOCKER_PLATFORM"    # e.g. linux/amd64, linux/arm64
#   echo "$MIESC_IS_ARM"             # true or false
#
# Usage (standalone):
#   ./scripts/detect-platform.sh     # prints platform info

# Detect host architecture and export variables
detect_platform() {
    local raw_arch
    raw_arch="$(uname -m)"

    case "$raw_arch" in
        x86_64|amd64)
            MIESC_HOST_ARCH="amd64"
            MIESC_DOCKER_PLATFORM="linux/amd64"
            MIESC_IS_ARM=false
            ;;
        aarch64|arm64)
            MIESC_HOST_ARCH="arm64"
            MIESC_DOCKER_PLATFORM="linux/arm64"
            MIESC_IS_ARM=true
            ;;
        *)
            MIESC_HOST_ARCH="$raw_arch"
            MIESC_DOCKER_PLATFORM="linux/$raw_arch"
            MIESC_IS_ARM=false
            ;;
    esac

    export MIESC_HOST_ARCH
    export MIESC_DOCKER_PLATFORM
    export MIESC_IS_ARM
}

# Check if the :full image has a native manifest for the current architecture.
# Returns 0 if a native manifest exists, 1 otherwise.
check_full_image_availability() {
    local image="${1:-ghcr.io/fboiero/miesc:full}"

    if ! command -v docker &> /dev/null; then
        return 1
    fi

    # docker manifest inspect returns the manifest list; grep for native arch
    if docker manifest inspect "$image" 2>/dev/null \
        | grep -q "\"architecture\":.*\"$MIESC_HOST_ARCH\""; then
        return 0
    else
        return 1
    fi
}

# Print detected platform information
print_platform_info() {
    echo "Platform detection:"
    echo "  Host architecture : $(uname -m) (normalized: $MIESC_HOST_ARCH)"
    echo "  Docker platform   : $MIESC_DOCKER_PLATFORM"
    echo "  ARM host          : $MIESC_IS_ARM"
}

# Auto-detect on source / execution
detect_platform

# If executed directly (not sourced), print info
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    print_platform_info
fi
