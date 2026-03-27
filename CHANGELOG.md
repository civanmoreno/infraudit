# Changelog

Todos los cambios notables en este proyecto se documentan en este archivo.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es/1.1.0/),
y el proyecto adhiere a [Semantic Versioning](https://semver.org/lang/es/).

## [2.1.0] - 2026-03-27

### Agregado
- **OS Detection**: Nuevo paquete `internal/osinfo` que detecta distribución, familia (Debian/RedHat/SUSE/Alpine/Arch), package manager e init system via `/etc/os-release`
- **Status SKIPPED**: Nuevo status para checks que no aplican al OS/init system detectado. Excluidos del scoring
- **OS info en reportes**: Información del OS detectado en console, JSON, YAML, HTML, Markdown y SARIF
- **24 checks con RequiredInit("systemd")**: BAK-001, CRON-001, FS-011, FS-012, LOG-001, LOG-002, NFS-002, NFS-004, PKG-004, SVC-001, SVC-003, SVC-007, SVC-009, SVC-010, SVC-012, SVC-013, SVC-014-027, SVC-049
- **CRYPTO-001 como RedHat-only**: Anotado con `SupportedOS: ["redhat"]`
- **SVC-052 como Debian-only**: Anotado con `SupportedOS: ["debian"]`
- **Plugin system YAML**: Checks personalizados en `/etc/infraudit/checks.d/*.yaml` sin recompilar. 6 tipos de regla: `file_exists`, `file_missing`, `file_contains`, `file_not_contains`, `file_perms`, `command`
- **Comando `baseline`**: `save`, `check`, `show`, `clear` para detección de regresiones. Exit code 1 si hay regresiones
- **SVC-057**: Nuevo check de autenticación Redis (`requirepass`)
- **Standards & Methodology**: Nueva página HTML documentando fuentes (CIS, STIG, NIST), metodología y mapeo a PCI-DSS, SOC 2, HIPAA, ISO 27001, FedRAMP
- **SECURITY.md**: Política de reporte de vulnerabilidades
- **CONTRIBUTING.md**: Guía de contribución con patrones de desarrollo, convenciones de commits e IDs de checks
- **Issue templates**: Bug report, solicitud de nuevo check, solicitud de feature
- **PR template**: Checklist de tests, lint, docs, CIS mapping
- **FUNDING.yml**: GitHub Sponsors habilitado
- **~270 tests nuevos**: Cobertura de 10.3% a 35.9% en 12 paquetes

### Corregido
- **SVC-052**: Removido `RequiredInit("systemd")` — el check usa `PkgInstalled` que no requiere systemd (#25)
- **baseline check**: Usaba `AllEntries` (con tag `json:"-"`) para comparar baseline, resultando en todos los checks como "new". Ahora usa `Entries` (#26)
- **Checks actualizados a `check.P()`**: 20+ archivos de checks actualizados para usar `check.P()` en rutas de archivos, habilitando test isolation via FSRoot
- **gofmt y gosec**: Resueltos todos los warnings de golangci-lint en archivos de test

### Cambiado
- **doctor command**: Ahora muestra OS detectado, familia, package manager e init system
- **Coverage CI**: Ahora corre coverage en todos los paquetes (`./...`) en vez de solo los core
- **Release CI**: Solo crea release cuando el tag no existe (evita sobreescribir releases)
- **Release notes**: Usa `RELEASE_NOTES.md` en vez de auto-generated notes

## [2.0.0] - 2026-03-25

### Agregado
- 66 checks nuevos (221 → 287 total) para cobertura CIS completa
- SSH advanced: 7 checks (ClientAlive, LogLevel, UsePAM, DisableForwarding, GSSAPI, Kerberos)
- Firewall detailed: 8 checks (default deny, loopback, outbound, established, IPv6 rules)
- Kernel hardening: 10 checks (BPF, kexec, kptr_restrict, perf_event, SysRq, namespaces)
- Filesystem permissions: 17 checks (cron dirs, at/cron allow, sshd_config, gshadow)
- Logging advanced: 8 checks (journald forward, rsyslog remote, audit immutable)
- PAM advanced: 8 checks (nullok, securetty, login.defs UID/GID/UMASK/ENCRYPT)
- Services advanced: 8 checks (rpcbind, XDMCP, prelink, apport, tftp, ldap, talk, rsh)
- Remediación en 100% de los 287 checks

## [1.1.0] - 2026-03-22

### Agregado
- Comando `explain` con CIS/STIG mapping y remediación detallada
- Comando `top` para findings más críticos
- Comando `diff` para comparar dos reportes JSON
- Comando `scan` para auditoría remota via SSH
- Formato SARIF para integración con GitHub/GitLab
- Comando `doctor` para diagnóstico de readiness
- Policy-as-code con `--enforce-policy`
- Comando `compliance` para reporte CIS Benchmark
- Formato Markdown
- Hardening Index (scoring 0-100 con grades A-F)
- HTML report autocontenido
- Shell completion
- Man page

## [1.0.0] - 2026-03-19

### Agregado
- 132 checks iniciales en 17 categorías
- Formatos de salida: console, JSON, YAML
- Perfiles de servidor (web-server, db-server, container-host, minimal)
- Configuración via JSON files (system, user, directory)
- Ejecución paralela con `--parallel`
- Command timeouts
- CI/CD con tests, lint, race detector, SBOM, cosign signing
