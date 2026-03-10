#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<EOF
Usage: ./scripts/release.sh <major|minor|patch> [--dry-run]

Runs the full release pipeline:
  1. Bump version in Cargo.toml + sync to flake.nix
  2. Run local quality gates (fmt, clippy, test)
  3. Commit, tag

Options:
  major|minor|patch   Semver bump type (required)
  --dry-run           Show what would happen without making changes

Examples:
  ./scripts/release.sh patch
  ./scripts/release.sh minor --dry-run
EOF
}

BUMP=""
DRY_RUN=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    major|minor|patch) BUMP="$1"; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$BUMP" ]; then
  echo "Error: version bump type required (major, minor, or patch)" >&2
  usage >&2
  exit 1
fi

# Abort if working tree is dirty
if ! git diff --quiet HEAD 2>/dev/null; then
  echo "Error: working tree has uncommitted changes. Commit or stash them first." >&2
  git status --short
  exit 1
fi

# --- 1. Version bump ---
OLD_VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')

IFS='.' read -r MAJOR MINOR PATCH <<< "$OLD_VERSION"

case "$BUMP" in
  major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
  minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
  patch) PATCH=$((PATCH + 1)) ;;
esac

NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
echo "Version: $OLD_VERSION → $NEW_VERSION"

if $DRY_RUN; then
  echo ""
  echo "[dry-run] Would update Cargo.toml: version = \"$OLD_VERSION\" → \"$NEW_VERSION\""
  echo "[dry-run] Would update flake.nix:  version = \"$OLD_VERSION\" → \"$NEW_VERSION\""
  echo "[dry-run] Would regenerate Cargo.lock"
  echo "[dry-run] Would run: just check && just test"
  echo "[dry-run] Would commit: chore: release v${NEW_VERSION}"
  echo "[dry-run] Would tag: v${NEW_VERSION}"
  echo ""
  echo "No changes made."
  exit 0
fi

# Update Cargo.toml (portable: works with both GNU and BSD sed)
sed "s/^version = \"$OLD_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml > Cargo.toml.tmp && mv Cargo.toml.tmp Cargo.toml

# Sync version to flake.nix
sed "s/version = \"$OLD_VERSION\"/version = \"$NEW_VERSION\"/" flake.nix > flake.nix.tmp && mv flake.nix.tmp flake.nix

# Update Cargo.lock
cargo generate-lockfile --quiet 2>/dev/null || cargo check --quiet 2>/dev/null || true

# --- 2. Quality gates ---
echo ""
echo "Running quality gates..."
just check
just test
# Nix build runs in CI only (Linux targets); skip locally.

# --- 3. Commit + tag ---
echo ""
echo "Committing release..."
git add Cargo.toml Cargo.lock flake.nix
git commit -m "$(cat <<EOF
chore: release v${NEW_VERSION}
EOF
)"
git tag -a "v${NEW_VERSION}" -m "Release v${NEW_VERSION}"

echo ""
echo "=== Release v${NEW_VERSION} complete ==="
echo "Commit: $(git rev-parse --short HEAD)"
echo "Tag:    v${NEW_VERSION}"
echo ""
echo "Next steps:"
echo "  git push && git push --tags"
