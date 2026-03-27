# Proceso de Release

## Versionado

infraudit sigue [Semantic Versioning](https://semver.org/lang/es/):

- **MAJOR** (X.0.0): Cambios incompatibles (nuevo formato de config, checks renombrados)
- **MINOR** (x.Y.0): Nuevas funcionalidades (nuevos checks, nuevos comandos, nuevos formatos)
- **PATCH** (x.y.Z): Bug fixes, mejoras de documentación, correcciones de falsos positivos

## Antes del Release

### 1. Verificar que main está limpio

```bash
git checkout main
git pull
go build ./...
go test -race -count=1 ./...
golangci-lint run
```

### 2. Actualizar la versión

Editar `internal/version/version.go`:

```go
const (
    Version = "X.Y.Z"  // <-- nueva versión
    Name    = "infraudit"
)
```

### 3. Actualizar CHANGELOG.md

Agregar la nueva sección al inicio del archivo siguiendo el formato [Keep a Changelog](https://keepachangelog.com/):

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Agregado
- ...

### Corregido
- ...

### Cambiado
- ...
```

### 4. Actualizar RELEASE_NOTES.md

Reemplazar el contenido con las notas para esta versión. Este archivo es usado por el CI para el body del GitHub Release.

### 5. Actualizar versión en documentación

Verificar que la versión esté actualizada en:
- `docs/*.html` (sidebar version badge)
- `README.md` (sample output, si referencia versión)

### 6. Crear PR de release

```bash
git checkout -b release/vX.Y.Z
git add -A
git commit -m "release: vX.Y.Z"
git push -u origin release/vX.Y.Z
gh pr create --title "release: vX.Y.Z" --body "Release X.Y.Z — ver CHANGELOG.md"
```

### 7. Merge y verificar

1. Merge el PR a main
2. CI automáticamente:
   - Ejecuta tests + lint
   - Compila binarios (linux/amd64 + linux/arm64)
   - Genera checksums SHA256
   - Genera SBOM (SPDX)
   - Firma binarios con cosign (Sigstore)
   - Crea GitHub Release con tag `vX.Y.Z`
   - Adjunta: binarios, firmas, checksums, SBOM

### 8. Verificar el release

```bash
# Verificar que el tag existe
git pull --tags
git tag -l | grep vX.Y.Z

# Verificar el release en GitHub
gh release view vX.Y.Z

# Verificar la descarga
curl -sL https://github.com/civanmoreno/infraudit/releases/download/vX.Y.Z/infraudit-linux-amd64 -o /tmp/infraudit
chmod +x /tmp/infraudit
/tmp/infraudit --version

# Verificar firma
cosign verify-blob \
  --signature https://github.com/civanmoreno/infraudit/releases/download/vX.Y.Z/infraudit-linux-amd64.sig \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer-regexp ".*" \
  /tmp/infraudit
```

### 9. Actualizar Homebrew formula

```bash
# Actualizar SHA256 y versión en la formula
./scripts/update-formula.sh X.Y.Z

# Verificar la formula
cat Formula/infraudit.rb

# Commit y push
git add Formula/infraudit.rb
git commit -m "chore: update Homebrew formula to vX.Y.Z"
git push
```

Los usuarios pueden instalar via:
```bash
brew tap civanmoreno/tap https://github.com/civanmoreno/infraudit.git
brew install infraudit
```

## Qué incluye cada release

| Archivo | Descripción |
|---------|-------------|
| `infraudit-linux-amd64` | Binario estático para x86_64 |
| `infraudit-linux-arm64` | Binario estático para ARM64 (Graviton, Ampere) |
| `infraudit-linux-amd64.sig` | Firma cosign (Sigstore) |
| `infraudit-linux-arm64.sig` | Firma cosign (Sigstore) |
| `checksums.txt` | SHA256 de todos los binarios |
| `sbom.spdx.json` | Software Bill of Materials (SPDX) |

## Notas

- El CI solo crea un release si el tag `vX.Y.Z` no existe. Si necesitas re-publicar, elimina el tag y release primero.
- La versión fuente de verdad es `internal/version/version.go`. El CI la lee de ahí.
- No crear tags manualmente — el CI crea el tag automáticamente al crear el release.
- Los release notes vienen de `RELEASE_NOTES.md`, no de auto-generated.
