#!/bin/bash
# Retag a specific MIESC Docker release as :latest on GHCR.
#
# Usage:
#   scripts/retag_docker_latest.sh [VERSION]
#
# Example:
#   scripts/retag_docker_latest.sh 5.1.5
#
# Requires: docker, gh (GitHub CLI) authenticated with packages:write scope.

set -euo pipefail

REPO="ghcr.io/fboiero/miesc"
VERSION="${1:-5.1.5}"

# 1. Docker daemon
docker info > /dev/null 2>&1 || { echo "Docker is not running. Start it first (colima start)."; exit 1; }

# 2. GHCR login
echo "Logging into GHCR..."
echo "$(gh auth token)" | docker login ghcr.io -u fboiero --password-stdin

# 3. Retag standard image → latest
echo "Retagging ${VERSION} -> latest..."
docker pull "${REPO}:${VERSION}"
docker tag "${REPO}:${VERSION}" "${REPO}:latest"
docker push "${REPO}:latest"

# 4. Retag full image → full (if it exists for this version)
echo "Retagging ${VERSION}-full -> full..."
if docker pull "${REPO}:${VERSION}-full" 2>/dev/null; then
  docker tag "${REPO}:${VERSION}-full" "${REPO}:full"
  docker push "${REPO}:full"
  echo "full retagged"
else
  echo "${VERSION}-full not found on GHCR, skipping"
fi

# 5. Verify
echo "Verifying..."
docker manifest inspect "${REPO}:latest" | head -5
docker run --rm "${REPO}:latest" version
echo "Done — latest now points to ${VERSION}"
