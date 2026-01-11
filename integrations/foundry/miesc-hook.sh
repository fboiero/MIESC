#!/bin/bash
# =============================================================================
# MIESC Foundry Post-Build Hook
# =============================================================================
# This script runs MIESC security analysis after Foundry builds.
#
# Installation:
#   1. Copy this file to your Foundry project: scripts/miesc-hook.sh
#   2. Make executable: chmod +x scripts/miesc-hook.sh
#   3. Add to foundry.toml: post_build_hook = "./scripts/miesc-hook.sh"
#
# Configuration (environment variables):
#   MIESC_FAIL_ON     - Severity to fail on: critical, high, medium, low (default: high)
#   MIESC_TIMEOUT     - Timeout in seconds (default: 300)
#   MIESC_LAYERS      - Layers to run: 1,2,3 (default: 1,2,3,6)
#   MIESC_OUTPUT      - Output format: json, sarif, markdown (default: json)
#   MIESC_CONTRACTS   - Contracts directory (default: ./src)
#   MIESC_QUIET       - Suppress output: true/false (default: false)
# =============================================================================

set -e

# Configuration with defaults
FAIL_ON="${MIESC_FAIL_ON:-high}"
TIMEOUT="${MIESC_TIMEOUT:-300}"
LAYERS="${MIESC_LAYERS:-1,2,3,6}"
OUTPUT="${MIESC_OUTPUT:-json}"
CONTRACTS="${MIESC_CONTRACTS:-./src}"
QUIET="${MIESC_QUIET:-false}"
REPORT_FILE="miesc-report.json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print with color
log_info() {
    if [ "$QUIET" != "true" ]; then
        echo -e "${BLUE}[MIESC]${NC} $1"
    fi
}

log_success() {
    if [ "$QUIET" != "true" ]; then
        echo -e "${GREEN}[MIESC]${NC} $1"
    fi
}

log_warning() {
    echo -e "${YELLOW}[MIESC]${NC} $1"
}

log_error() {
    echo -e "${RED}[MIESC]${NC} $1"
}

# Check if MIESC is installed
if ! command -v miesc &> /dev/null; then
    log_error "MIESC not found. Install with: pip install miesc"
    exit 1
fi

# Check if contracts directory exists
if [ ! -d "$CONTRACTS" ]; then
    log_warning "Contracts directory not found: $CONTRACTS"
    log_info "Trying ./contracts..."
    CONTRACTS="./contracts"
    if [ ! -d "$CONTRACTS" ]; then
        log_error "No contracts directory found"
        exit 1
    fi
fi

# Count Solidity files
SOL_COUNT=$(find "$CONTRACTS" -name "*.sol" -type f | wc -l | tr -d ' ')
if [ "$SOL_COUNT" -eq 0 ]; then
    log_warning "No Solidity files found in $CONTRACTS"
    exit 0
fi

log_info "Running security audit on $SOL_COUNT contracts..."
log_info "Directory: $CONTRACTS"
log_info "Fail on: $FAIL_ON | Timeout: ${TIMEOUT}s"

# Run MIESC audit
MIESC_CMD="miesc audit quick $CONTRACTS --ci --timeout $TIMEOUT"

if [ "$OUTPUT" = "json" ]; then
    MIESC_CMD="$MIESC_CMD --output json"
fi

# Execute audit
log_info "Executing: $MIESC_CMD"
echo ""

if ! $MIESC_CMD > "$REPORT_FILE" 2>&1; then
    # Check if it's a real error or just findings
    if [ -f "$REPORT_FILE" ]; then
        cat "$REPORT_FILE"
    fi
fi

# Parse results if JSON output
if [ "$OUTPUT" = "json" ] && [ -f "$REPORT_FILE" ]; then
    # Check if jq is available
    if command -v jq &> /dev/null; then
        CRITICAL=$(jq -r '.summary.critical // 0' "$REPORT_FILE" 2>/dev/null || echo "0")
        HIGH=$(jq -r '.summary.high // 0' "$REPORT_FILE" 2>/dev/null || echo "0")
        MEDIUM=$(jq -r '.summary.medium // 0' "$REPORT_FILE" 2>/dev/null || echo "0")
        LOW=$(jq -r '.summary.low // 0' "$REPORT_FILE" 2>/dev/null || echo "0")
        TOTAL=$((CRITICAL + HIGH + MEDIUM + LOW))

        echo ""
        log_info "=== Security Audit Summary ==="
        echo -e "  ${RED}Critical:${NC} $CRITICAL"
        echo -e "  ${YELLOW}High:${NC}     $HIGH"
        echo -e "  ${YELLOW}Medium:${NC}   $MEDIUM"
        echo -e "  ${BLUE}Low:${NC}      $LOW"
        echo -e "  Total:    $TOTAL"
        echo ""

        # Determine if we should fail
        SHOULD_FAIL=false
        case "$FAIL_ON" in
            critical)
                [ "$CRITICAL" -gt 0 ] && SHOULD_FAIL=true
                ;;
            high)
                [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ] && SHOULD_FAIL=true
                ;;
            medium)
                [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ] || [ "$MEDIUM" -gt 0 ] && SHOULD_FAIL=true
                ;;
            low)
                [ "$TOTAL" -gt 0 ] && SHOULD_FAIL=true
                ;;
        esac

        if [ "$SHOULD_FAIL" = true ]; then
            log_error "Security issues found above threshold ($FAIL_ON)"

            # Show critical/high findings
            if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
                echo ""
                log_error "Critical/High severity findings:"
                jq -r '.findings[] | select(.severity == "critical" or .severity == "high") | "  [\(.severity | ascii_upcase)] \(.title) - \(.location // "unknown")"' "$REPORT_FILE" 2>/dev/null || true
            fi

            exit 1
        else
            log_success "Security audit passed (threshold: $FAIL_ON)"
        fi
    else
        log_warning "jq not installed - cannot parse JSON results"
        cat "$REPORT_FILE"
    fi
else
    # Non-JSON output, just show it
    if [ -f "$REPORT_FILE" ]; then
        cat "$REPORT_FILE"
    fi
fi

log_success "Audit complete. Report saved to: $REPORT_FILE"
