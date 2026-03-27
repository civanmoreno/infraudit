# infraudit GitHub Action

Run infraudit security audits in your CI/CD pipeline — on the GitHub Actions runner or on remote servers via SSH.

## Modos de Ejecución

| Modo | Uso | Cuándo usarlo |
|------|-----|---------------|
| `local` | Audita el runner de GitHub Actions | Testing de containers, validación de imágenes base, auditoría del entorno CI |
| `ssh` | Audita un servidor remoto via SSH | Servidores de producción, staging, pre-deploy checks |

## Uso Rápido

### Modo Local (en el runner)

```yaml
- name: Security Audit
  uses: civanmoreno/infraudit/action@v2
  with:
    min-score: 70
```

### Modo SSH (servidor remoto)

```yaml
- name: Security Audit (Production)
  uses: civanmoreno/infraudit/action@v2
  with:
    mode: ssh
    host: deploy@production.example.com
    ssh-key: ${{ secrets.SSH_PRIVATE_KEY }}
    min-score: 80
```

## Ejemplos Completos

### Auditoría básica con gate de score

```yaml
name: Security Audit
on:
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run infraudit
        uses: civanmoreno/infraudit/action@v2
        id: audit
        with:
          min-score: 70

      - name: Show results
        run: |
          echo "Score: ${{ steps.audit.outputs.score }}/100 (${{ steps.audit.outputs.grade }})"
          echo "Passed: ${{ steps.audit.outputs.passed }}/${{ steps.audit.outputs.total }}"
```

### Auditoría de servidor de producción via SSH

```yaml
name: Production Security Check
on:
  schedule:
    - cron: '0 6 * * 1'  # Cada lunes a las 6am

jobs:
  audit-prod:
    runs-on: ubuntu-latest
    steps:
      - name: Audit production server
        uses: civanmoreno/infraudit/action@v2
        id: audit
        with:
          mode: ssh
          host: deploy@prod.example.com:22
          ssh-key: ${{ secrets.PROD_SSH_KEY }}
          profile: web-server
          min-score: 75
          format: sarif

      - name: Alert on low score
        if: failure()
        run: echo "::warning::Production score dropped below 75!"
```

### Auditoría de múltiples servidores

```yaml
name: Fleet Security Audit
on:
  schedule:
    - cron: '0 2 * * *'  # Diario a las 2am

jobs:
  audit:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        server:
          - { name: web-1, host: "deploy@web1.example.com", profile: web-server }
          - { name: db-1, host: "deploy@db1.example.com", profile: db-server }
          - { name: api-1, host: "deploy@api1.example.com", profile: web-server }
      fail-fast: false
    steps:
      - name: Audit ${{ matrix.server.name }}
        uses: civanmoreno/infraudit/action@v2
        id: audit
        with:
          mode: ssh
          host: ${{ matrix.server.host }}
          ssh-key: ${{ secrets.FLEET_SSH_KEY }}
          profile: ${{ matrix.server.profile }}
          min-score: 70
```

### Con SARIF para GitHub Code Scanning

```yaml
- name: Security Audit
  uses: civanmoreno/infraudit/action@v2
  with:
    format: sarif
    category: auth,network,crypto
```

Los resultados aparecen en la pestaña **Security > Code Scanning** del repositorio.

### Con policy enforcement

```yaml
- name: Security Audit
  uses: civanmoreno/infraudit/action@v2
  with:
    mode: ssh
    host: deploy@staging.example.com
    ssh-key: ${{ secrets.SSH_KEY }}
    policy: .infraudit-policy.json
```

### Solo categorías específicas

```yaml
- name: SSH & Auth Audit
  uses: civanmoreno/infraudit/action@v2
  with:
    category: auth,pam,crypto
    severity-min: high
    min-score: 80
```

## Inputs

| Input | Default | Descripción |
|-------|---------|-------------|
| `mode` | `local` | `local` (runner GHA) o `ssh` (servidor remoto) |
| `host` | — | Host SSH: `user@hostname` o `user@hostname:port` |
| `ssh-key` | — | Llave privada SSH para autenticación |
| `ssh-password` | — | Password SSH (si no usa key) |
| `ssh-known-hosts` | — | Contenido de known_hosts (si vacío, desactiva verificación) |
| `category` | — | Filtrar por categoría (comma-separated) |
| `profile` | — | Perfil de servidor: `web-server`, `db-server`, `container-host`, `minimal` |
| `skip` | — | Check IDs a saltar (comma-separated) |
| `severity-min` | — | Severidad mínima: `low`, `medium`, `high`, `critical` |
| `format` | `sarif` | Formato: `console`, `json`, `sarif` |
| `args` | — | Argumentos adicionales para `infraudit audit` |
| `policy` | — | Ruta al archivo de policy |
| `min-score` | — | Score mínimo (0-100). Falla si está por debajo |
| `version` | `latest` | Versión de infraudit a usar |

## Outputs

| Output | Descripción |
|--------|-------------|
| `score` | Hardening Index (0-100) |
| `grade` | Letra (A-F) |
| `total` | Total de checks ejecutados |
| `passed` | Checks que pasaron |
| `failures` | Checks que fallaron |
| `warnings` | Warnings |
| `report-path` | Ruta al reporte JSON generado |

## Job Summary

La action genera automáticamente un resumen en el tab **Summary** del workflow con:
- Score y grade
- Conteo de checks por status
- Tabla de hallazgos CRITICAL y HIGH

## Seguridad

- Las llaves SSH se eliminan automáticamente al finalizar (even on failure)
- Si no se provee `ssh-known-hosts`, se desactiva `StrictHostKeyChecking` (no recomendado para producción)
- Para producción, siempre provee `ssh-known-hosts` con el fingerprint del servidor
- Los secrets deben almacenarse como [GitHub Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
