#!/usr/bin/env bash
# ptreport installer - one command:  ./install.sh
#
# Creates an isolated virtualenv, installs pinned + hash-verified dependencies
# from requirements.lock, and puts the `ptreport` command on your PATH.
# Your data (SQLite DB, secrets) lives separately in ~/.local/share/ptreport/data
# and is never touched by (re)installing or uninstalling.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_HOME="${PTREPORT_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/ptreport}"
VENV="$APP_HOME/venv"
BIN_DIR="${PTREPORT_BIN_DIR:-$HOME/.local/bin}"

TECTONIC_DIR="$APP_HOME/tectonic"

if [[ "${1:-}" == "--uninstall" ]]; then
  rm -rf "$VENV" "$TECTONIC_DIR"
  rm -f "$BIN_DIR/ptreport"
  echo "ptreport uninstalled. Your data was kept in $APP_HOME/data"
  exit 0
fi

find_python() {
  for candidate in "${PYTHON:-}" python3.14 python3.13 python3.12 python3.11 python3.10 python3; do
    [[ -z "$candidate" ]] && continue
    if command -v "$candidate" >/dev/null 2>&1 &&
       "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
      echo "$candidate"; return 0
    fi
  done
  return 1
}

PY="$(find_python)" || { echo "error: Python 3.10+ is required (set PYTHON=/path/to/python)." >&2; exit 1; }
"$PY" -c 'import venv, ensurepip' 2>/dev/null || {
  echo "error: Python venv module missing. On Debian/Kali/Ubuntu: sudo apt install python3-venv" >&2; exit 1; }

echo "==> Using $("$PY" --version) ($PY)"
echo "==> Creating virtualenv in $VENV"
mkdir -p "$APP_HOME"
"$PY" -m venv --clear "$VENV"

echo "==> Installing pinned dependencies (hash-verified)"
"$VENV/bin/python" -m pip install --quiet --disable-pip-version-check --require-hashes -r "$SRC_DIR/requirements.lock"

echo "==> Installing ptreport"
"$VENV/bin/python" -m pip install --quiet --disable-pip-version-check --no-deps "$SRC_DIR"

# --- LaTeX engine (Tectonic): PDF reports are typeset from the LaTeX template --------------------------
# Pinned version + SHA-256 from the GitHub release (asset digests). Installed next to the app, no sudo.
TECTONIC_VERSION="0.17.0"
install_tectonic() {
  local os arch target sha url tmp
  os="$(uname -s)"; arch="$(uname -m)"
  case "$os/$arch" in
    Linux/x86_64)          target="x86_64-unknown-linux-musl";  sha="8533d07f9ccbd7a65824b9e0459041bca34af1eb33daba48f59215593753a3b7" ;;
    Linux/aarch64|Linux/arm64) target="aarch64-unknown-linux-musl"; sha="b10954a95404f3ab2328d2fa59a5ebab8e657f893fab096f98be8db7c0c979b8" ;;
    Darwin/x86_64)         target="x86_64-apple-darwin";        sha="7c90ef5b6ddb1eb1937e4337add5237b79338e4b9676459fa91187d24d6cdf80" ;;
    Darwin/arm64)          target="aarch64-apple-darwin";       sha="a3f1cac7c5678f01661a92212f58480ae3b0634115d880dbc59e2953ded45667" ;;
    *) echo "WARNING: no Tectonic build for $os/$arch; PDF export will use xelatex/lualatex if installed." >&2; return 0 ;;
  esac
  if [[ -x "$TECTONIC_DIR/tectonic" ]] && "$TECTONIC_DIR/tectonic" --version 2>/dev/null | grep -q "$TECTONIC_VERSION"; then
    echo "==> Tectonic $TECTONIC_VERSION already installed"; return 0
  fi
  url="https://github.com/tectonic-typesetting/tectonic/releases/download/tectonic%40${TECTONIC_VERSION}/tectonic-${TECTONIC_VERSION}-${target}.tar.gz"
  tmp="$(mktemp -d)"
  echo "==> Downloading Tectonic $TECTONIC_VERSION (LaTeX engine for PDF reports)"
  if ! curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/tectonic.tar.gz" "$url"; then
    echo "WARNING: could not download Tectonic; PDF export needs it (or xelatex). Re-run ./install.sh later." >&2
    rm -rf "$tmp"; return 0
  fi
  if ! echo "$sha  $tmp/tectonic.tar.gz" | sha256sum -c --quiet - 2>/dev/null &&
     ! echo "$sha  $tmp/tectonic.tar.gz" | shasum -a 256 -c --quiet - 2>/dev/null; then
    echo "ERROR: Tectonic checksum mismatch, refusing to install it." >&2
    rm -rf "$tmp"; return 1
  fi
  mkdir -p "$TECTONIC_DIR"
  tar -xzf "$tmp/tectonic.tar.gz" -C "$tmp"
  install -m 0755 "$tmp/tectonic" "$TECTONIC_DIR/tectonic"
  rm -rf "$tmp"
}
install_tectonic

mkdir -p "$BIN_DIR"
ln -sf "$VENV/bin/ptreport" "$BIN_DIR/ptreport"

# Typeset a sample report once so the LaTeX packages are downloaded and cached now;
# after that PDF export works offline.
echo "==> Preparing the LaTeX template (first run downloads LaTeX packages, ~1-2 min)"
if ! PTREPORT_TECTONIC="$TECTONIC_DIR/tectonic" "$VENV/bin/ptreport" --warm-latex; then
  echo "WARNING: LaTeX warm-up failed (offline?). PDF export will fetch packages on first use." >&2
fi

echo
echo "ptreport installed: $BIN_DIR/ptreport"
case ":$PATH:" in
  *":$BIN_DIR:"*) echo "Run it with:  ptreport" ;;
  *) echo "NOTE: $BIN_DIR is not on your PATH. Add this to your shell profile:"
     echo "  export PATH=\"$BIN_DIR:\$PATH\""
     echo "Or run directly:  $BIN_DIR/ptreport" ;;
esac
