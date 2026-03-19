# Releasing

## Versioning

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html):

- **PATCH** (x.y.Z): Bug fixes, config tweaks, doc corrections
- **MINOR** (x.Y.0): New features, new alert categories, new endpoints
- **MAJOR** (X.0.0): Breaking changes to webhook format, config env vars, or annotation schema

Version is defined in `Cargo.toml` (single source of truth) and synced to `flake.nix` by the release script.

## Changelog

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/):

1. During development, add entries under `[Unreleased]` with appropriate category (Added, Changed, Fixed, etc.)
2. Write entries in imperative mood ("Add feature" not "Added feature")
3. The release script automatically moves `[Unreleased]` entries to a versioned `[x.y.z] - YYYY-MM-DD` section — no manual step needed

## Release Workflow

### Pre-release (during development)

Update `CHANGELOG.md` under `[Unreleased]` as you work. Commit changelog entries alongside the code they describe.

### Cutting a release

1. **Run the release**:
   ```bash
   just release patch   # or minor, or major
   ```

   The script (`scripts/release.sh`) will:
   - Bump version in `Cargo.toml` and sync to `flake.nix`
   - Move `[Unreleased]` changelog entries to a `[X.Y.Z] - YYYY-MM-DD` section automatically
   - Run local quality gates: `just check && just test`
   - Commit everything in a single commit: `chore: release vX.Y.Z` (version bump + changelog)
   - Create annotated tag: `vX.Y.Z`

   Any uncommitted changes outside `CHANGELOG.md` will cause the script to abort.

   CI still runs `nix build` on Linux after push. Local release gating does not require `nix build` on Darwin hosts.

2. **Push** (when remote is configured):
   ```bash
   git push && git push --tags
   ```

### Quick reference

```bash
just version              # Show current version
just pre-release          # Run quality gates without releasing
just release-dry-run patch  # Preview what a patch release would do
just release patch        # Bump patch, gate, commit, tag
just release minor        # Bump minor, gate, commit, tag
just release major        # Bump major, gate, commit, tag
```

## Tag Format

Tags use the `vX.Y.Z` format (e.g., `v0.2.0`). Annotated with message "Release vX.Y.Z".

## Commit Convention

- Release commits: `chore: release vX.Y.Z` (single commit with version bump + changelog)
