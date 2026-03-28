## Highlights

### Man Page Restored
The man page (`docs/infraudit.1`) was accidentally deleted in v2.0.0. It has been restored and fully updated to v2.2.0 with documentation for all 12 commands, new flags (`--enforce-policy`, `--format sarif`), YAML plugin system, scan flags, and 15+ usage examples.

After installing via `install.sh`, run `man infraudit` for the full reference.

### Documentation Fully in English
All remaining Spanish-language files have been translated to English:
- `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, `action/README.md`

### Comparison Table
The [docs landing page](https://civanmoreno.github.io/infraudit/) now includes a "Why infraudit?" feature comparison table against Lynis, CIS-CAT Pro, and OpenSCAP.

### Consistency Fixes
- Go version references aligned to 1.25 across all files (matching `go.mod`)
- CIS Benchmark Level 2 coverage corrected to ~90% across all docs

## What's Changed

**Fixed:**
- Restored man page deleted in v2.0.0, updated for v2.2.0
- Go version inconsistency (1.24 → 1.25) in README, CONTRIBUTING, Dockerfile, HTML docs
- CIS Level 2 coverage inconsistency (~70% → ~90%) in README, docs/index.html

**Changed:**
- CHANGELOG.md translated to English
- SECURITY.md translated to English
- CONTRIBUTING.md translated to English
- action/README.md translated to English
- Comparison table added to docs/index.html

**Full Changelog**: https://github.com/civanmoreno/infraudit/compare/v2.2.0...v2.2.1
