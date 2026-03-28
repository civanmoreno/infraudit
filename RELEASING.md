# Release Process

## Versioning

infraudit follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (X.0.0): Breaking changes (new config format, renamed checks)
- **MINOR** (x.Y.0): New features (new checks, new commands, new formats)
- **PATCH** (x.y.Z): Bug fixes, documentation improvements, false positive corrections

## Before the Release

### 1. Verify that main is clean

```bash
git checkout main
git pull
go build ./...
go test -race -count=1 ./...
golangci-lint run
```

### 2. Update the version

Edit `internal/version/version.go`:

```go
const (
    Version = "X.Y.Z"  // <-- new version
    Name    = "infraudit"
)
```

### 3. Update CHANGELOG.md

Add the new section at the top of the file following the [Keep a Changelog](https://keepachangelog.com/) format:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- ...

### Fixed
- ...

### Changed
- ...
```

### 4. Update RELEASE_NOTES.md

Replace the content with the notes for this version. This file is used by CI for the GitHub Release body.

### 5. Update version in documentation

Verify the version is updated in:
- `docs/*.html` (sidebar version badge)
- `README.md` (sample output, if it references the version)

### 6. Create the release PR

```bash
git checkout -b release/vX.Y.Z
git add -A
git commit -m "release: vX.Y.Z"
git push -u origin release/vX.Y.Z
gh pr create --title "release: vX.Y.Z" --body "Release X.Y.Z — see CHANGELOG.md"
```

### 7. Merge and verify

1. Merge the PR to main
2. CI automatically:
   - Runs tests + lint
   - Compiles binaries (linux/amd64 + linux/arm64)
   - Generates SHA256 checksums
   - Generates SBOM (SPDX)
   - Signs binaries with cosign (Sigstore)
   - Creates GitHub Release with tag `vX.Y.Z`
   - Attaches: binaries, signatures, checksums, SBOM

### 8. Verify the release

```bash
# Verify the tag exists
git pull --tags
git tag -l | grep vX.Y.Z

# Verify the release on GitHub
gh release view vX.Y.Z

# Verify the download
curl -sL https://github.com/civanmoreno/infraudit/releases/download/vX.Y.Z/infraudit-linux-amd64 -o /tmp/infraudit
chmod +x /tmp/infraudit
/tmp/infraudit --version

# Verify signature
cosign verify-blob \
  --signature https://github.com/civanmoreno/infraudit/releases/download/vX.Y.Z/infraudit-linux-amd64.sig \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer-regexp ".*" \
  /tmp/infraudit
```

### 9. Update Homebrew formula

```bash
# Update SHA256 and version in the formula
./scripts/update-formula.sh X.Y.Z

# Verify the formula
cat Formula/infraudit.rb

# Commit and push
git add Formula/infraudit.rb
git commit -m "chore: update Homebrew formula to vX.Y.Z"
git push
```

Users can install via:
```bash
brew tap civanmoreno/tap https://github.com/civanmoreno/infraudit.git
brew install infraudit
```

## What each release includes

| File | Description |
|------|-------------|
| `infraudit-linux-amd64` | Static binary for x86_64 |
| `infraudit-linux-arm64` | Static binary for ARM64 (Graviton, Ampere) |
| `infraudit-linux-amd64.sig` | cosign signature (Sigstore) |
| `infraudit-linux-arm64.sig` | cosign signature (Sigstore) |
| `checksums.txt` | SHA256 of all binaries |
| `sbom.spdx.json` | Software Bill of Materials (SPDX) |

## Notes

- CI only creates a release if the tag `vX.Y.Z` doesn't exist. If you need to re-publish, delete the tag and release first.
- The version source of truth is `internal/version/version.go`. CI reads it from there.
- Do not create tags manually — CI creates the tag automatically when creating the release.
- Release notes come from `RELEASE_NOTES.md`, not auto-generated.
