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
  3. Commit (includes pending CHANGELOG.md changes), tag

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

# Allow uncommitted CHANGELOG.md changes (included in release commit).
# Abort if anything else is dirty.
DIRTY_FILES=$(git diff --name-only HEAD 2>/dev/null || true)
NON_CHANGELOG=$(echo "$DIRTY_FILES" | grep -v '^CHANGELOG.md$' | grep -v '^$' || true)
if [ -n "$NON_CHANGELOG" ]; then
  echo "Error: working tree has uncommitted changes outside CHANGELOG.md." >&2
  echo "Only CHANGELOG.md changes are allowed (they'll be included in the release commit)." >&2
  git status --short
  exit 1
fi
if [ -n "$DIRTY_FILES" ]; then
  echo "Including uncommitted CHANGELOG.md changes in release commit."
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
  echo "[dry-run] Would move CHANGELOG.md [Unreleased] entries to [${NEW_VERSION}] - $(date +%Y-%m-%d)"
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

# Move [Unreleased] entries to a versioned section in CHANGELOG.md.
# Inserts "## [X.Y.Z] - YYYY-MM-DD" after the "## [Unreleased]" header,
# preserving any content already under [Unreleased].
if [ -f CHANGELOG.md ]; then
  RELEASE_DATE=$(date +%Y-%m-%d)
  if grep -q '## \[Unreleased\]' CHANGELOG.md; then
    # Check if entries exist under [Unreleased] (non-empty lines before the next ## heading)
    HAS_ENTRIES=$(awk '/^## \[Unreleased\]/{found=1; next} found && /^## \[/{exit} found && /^[^[:space:]]/{print; exit}' CHANGELOG.md)
    if [ -n "$HAS_ENTRIES" ]; then
      # Insert versioned header after [Unreleased], with a blank line between.
      # Uses awk for portable newline insertion (BSD sed does not support \n in replacements).
      awk -v ver="$NEW_VERSION" -v date="$RELEASE_DATE" \
        '/^## \[Unreleased\]$/{print; print ""; print "## [" ver "] - " date; next} {print}' \
        CHANGELOG.md > CHANGELOG.md.tmp && mv CHANGELOG.md.tmp CHANGELOG.md
      echo "CHANGELOG.md: moved [Unreleased] entries to [${NEW_VERSION}] - ${RELEASE_DATE}"
    else
      echo "CHANGELOG.md: no entries under [Unreleased], skipping"
    fi
  else
    echo "CHANGELOG.md: no [Unreleased] section found, skipping"
  fi
fi

# --- 2. Quality gates ---
echo ""
echo "Running quality gates..."
just check
just test
# Nix build runs in CI only (Linux targets); skip locally.

# --- 3. Commit + tag ---
echo ""
echo "Committing release..."
git add Cargo.toml Cargo.lock flake.nix CHANGELOG.md
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
