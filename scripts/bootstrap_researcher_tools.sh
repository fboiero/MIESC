#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_311="${PYTHON_311:-python3.11}"
MAIN_PYTHON="${MAIN_PYTHON:-python3.12}"
UV_BIN="${UV_BIN:-uv}"
MIESC_MPLCONFIGDIR="${MIESC_MPLCONFIGDIR:-${TMPDIR:-/tmp}/miesc-matplotlib}"

log() {
  printf '[miesc-bootstrap] %s\n' "$*"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

ensure_python_311() {
  if have "$PYTHON_311"; then
    return
  fi

  if have "$UV_BIN"; then
    log "Installing Python 3.11 with uv"
    "$UV_BIN" python install 3.11
    PYTHON_311="$("$UV_BIN" python find 3.11)"
    return
  fi

  log "Python 3.11 not found. Install Python 3.11 or uv, then rerun this script."
  exit 1
}

ensure_main_venv() {
  if [ -x ".venv/bin/python" ]; then
    return
  fi

  local main_python="$MAIN_PYTHON"
  if ! have "$main_python"; then
    if have "$UV_BIN"; then
      log "Installing Python 3.12 with uv for MIESC runtime"
      "$UV_BIN" python install 3.12
      main_python="$("$UV_BIN" python find 3.12)"
    else
      log "Python 3.12 not found. Install Python 3.12 or uv, then rerun this script."
      exit 1
    fi
  fi

  log "Creating .venv for MIESC runtime"
  "$main_python" -m venv .venv
}

ensure_miesc_installed() {
  if .venv/bin/python -c "import miesc" >/dev/null 2>&1; then
    return
  fi

  log "Installing MIESC researcher dependencies in .venv"
  .venv/bin/pip install --upgrade pip setuptools wheel
  .venv/bin/pip install -e ".[researcher,pdf]"
}

ensure_venv() {
  local py="$1"
  local dir="$2"
  if [ ! -x "$dir/bin/python" ]; then
    log "Creating $dir"
    "$py" -m venv "$dir"
  fi
}

install_mythril() {
  ensure_venv "$PYTHON_311" ".tools/mythril"
  log "Installing Mythril in .tools/mythril"
  .tools/mythril/bin/pip install --upgrade pip 'setuptools<81' wheel mythril
  mkdir -p "$MIESC_MPLCONFIGDIR"
  MPLCONFIGDIR="$MIESC_MPLCONFIGDIR" .tools/mythril/bin/myth version
}

install_manticore() {
  if ! have "$UV_BIN"; then
    log "Manticore requires uv-managed Python 3.9 for reliable installation."
    exit 1
  fi

  log "Installing Python 3.9 with uv for Manticore"
  "$UV_BIN" python install 3.9
  if [ ! -x ".tools/manticore39/bin/python" ]; then
    "$UV_BIN" venv --python 3.9 .tools/manticore39
    .tools/manticore39/bin/python -m ensurepip --upgrade
  fi

  log "Installing Manticore in .tools/manticore39"
  .tools/manticore39/bin/pip3 install --upgrade pip 'setuptools<81' wheel manticore 'protobuf<3.21'
  PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python .tools/manticore39/bin/manticore --version
}

install_certora() {
  ensure_venv "$PYTHON_311" ".tools/certora"
  log "Installing Certora CLI in .tools/certora"
  .tools/certora/bin/pip install --upgrade pip setuptools wheel certora-cli
  .tools/certora/bin/certoraRun --version
}

install_wake() {
  ensure_venv "$PYTHON_311" ".tools/wake"
  log "Installing Wake in .tools/wake"
  .tools/wake/bin/pip install --upgrade pip setuptools wheel eth-wake
  .tools/wake/bin/wake --version
}

install_semgrep() {
  ensure_venv "$PYTHON_311" ".tools/semgrep"
  log "Installing Semgrep in .tools/semgrep"
  .tools/semgrep/bin/pip install --upgrade pip setuptools wheel semgrep
  .tools/semgrep/bin/semgrep --version
}

check_solc() {
  if have solc; then
    log "solc detected"
    solc --version | head -2 || true
    return
  fi

  log "solc not found. Install solc or solc-select before running formal verification."
}

main() {
  ensure_python_311
  ensure_main_venv
  ensure_miesc_installed
  mkdir -p .tools
  install_mythril
  install_manticore
  install_certora
  install_wake
  install_semgrep
  check_solc

  if [ -f apik.sh ]; then
    # shellcheck disable=SC1091
    . ./apik.sh >/dev/null 2>&1 || true
    if [ -n "${CERTORAKEY:-}" ] || [ -n "${CERTORA_KEY:-}" ]; then
      log "Certora key detected from apik.sh"
    else
      log "apik.sh found, but CERTORAKEY/CERTORA_KEY was not detected"
    fi
  else
    log "Optional: create apik.sh with CERTORAKEY or CERTORA_KEY for Certora runs"
  fi

  log "Running MIESC doctor"
  .venv/bin/python -m miesc.cli.main doctor
}

main "$@"
