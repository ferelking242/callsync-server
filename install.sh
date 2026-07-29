#!/usr/bin/env bash
# ============================================================
#  CallSync Server — Install Script for Replit
#  Usage: bash install.sh
#  Requires: GITHUB_PAT secret set in Replit Secrets
# ============================================================
set -euo pipefail

REPO="ferelking242/callsync-server"
BRANCH="main"
SUBDIR="callsync-server"   # subfolder inside the repo where main.go lives

echo "========================================"
echo "  CallSync Server — Replit Installer"
echo "========================================"

# ── 1. Clone repo ─────────────────────────────────────────
echo "[1/4] Cloning repository..."
if [ -z "${GITHUB_PAT:-}" ]; then
  echo "ERROR: GITHUB_PAT secret is not set."
  echo "Add it via Replit Secrets before running this script."
  exit 1
fi

TMPDIR=$(mktemp -d)
git clone --depth=1 --branch "$BRANCH" \
  "https://${GITHUB_PAT}@github.com/${REPO}.git" "$TMPDIR" 2>&1 | tail -3

# ── 2. Copy server files to workspace root ────────────────
echo "[2/4] Copying server files..."
rsync -av --exclude='.git' "$TMPDIR/$SUBDIR/" . \
  --exclude='callsync.db' --exclude='storage/' 2>&1 | grep -v '^sending\|^sent\|^total' || true
rm -rf "$TMPDIR"

# ── 3. Verify vendor + build ──────────────────────────────
echo "[3/4] Building Go binary..."
if [ ! -d vendor ]; then
  echo "  vendor/ missing — running go mod vendor..."
  go mod vendor
fi
go build -mod=vendor -o callsync-bin .
echo "  ✅ Build successful → callsync-bin"

# ── 4. Smoke-test ─────────────────────────────────────────
echo "[4/4] Verifying binary..."
if [ -f ./callsync-bin ]; then
  echo "  ✅ callsync-bin present and executable"
else
  echo "  ❌ Build failed — callsync-bin not found"
  exit 1
fi

echo ""
echo "========================================"
echo "  Installation complete!"
echo ""
echo "  Workflow command (set in Replit):"
echo "    go build -mod=vendor -o callsync-bin . && ./callsync-bin"
echo ""
echo "  Deploy config:"
echo "    Target : Reserved VM"
echo "    Build  : go build -mod=vendor -o callsync-bin ."
echo "    Run    : ./callsync-bin"
echo ""
echo "  Default credentials:"
echo "    Username : admin"
echo "    Password : admin123"
echo "========================================"
