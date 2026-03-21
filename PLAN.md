# infraudit — Plan de desarrollo

## Visión

CLI en Go que se ejecuta directamente en un servidor Linux para auditar su seguridad y organización. Valida configuraciones, permisos, servicios, red, usuarios y buenas prácticas de hardening según CIS Benchmarks, STIG y estándares de la industria. Genera un reporte con hallazgos categorizados por severidad.

## Referencias

- CIS Benchmarks (Ubuntu 24.04, RHEL 9, Debian 12)
- DISA STIG para Linux
- Lynis (categorías de auditoría)
- OWASP Docker Security Cheat Sheet

## Fases

### Fase 1: Scaffold inicial ✅

- [x] Inicializar módulo Go (`go mod init`)
- [x] Dependencia cobra para CLI
- [x] `main.go` — entry point
- [x] `cmd/root.go` — comando raíz con `--help`, `--version`
- [x] `internal/version/version.go` — constantes de versión (v0.1.0)

### Fase 2: Motor de auditoría y modelo de checks ✅

- [x] Definir interfaz `Check` (nombre, categoría, severidad, `Run() Result`)
- [x] Registry de checks con autodiscovery
- [x] Modelo de resultado: PASS / WARN / FAIL / ERROR con mensaje y remediación
- [x] `infraudit audit` — ejecuta todos los checks registrados
- [x] `infraudit audit --category <cat>` — filtra por categoría
- [x] `infraudit list` — lista todos los checks disponibles

### Fase 3: Checks de usuarios y autenticación (AUTH) ✅

- [x] Root login por SSH deshabilitado (`PermitRootLogin no`)
- [x] Autenticación por password SSH deshabilitada (`PasswordAuthentication no`)
- [x] Usuarios con UID 0 (solo root debe tenerlo)
- [x] Usuarios sin password o con password vacío
- [x] Cuentas del sistema con shell de login (deben tener `/nologin` o `/false`)
- [x] Archivo sudoers: uso de `NOPASSWD` excesivo
- [x] Permisos de `/etc/passwd`, `/etc/shadow`, `/etc/group`
- [x] Restricción de `su` vía `pam_wheel.so` (solo grupo autorizado)

### Fase 4: Checks de PAM y políticas de contraseñas (PAM) ✅

- [x] Calidad de passwords vía `pam_pwquality` (minlen, dcredit, ucredit, lcredit, ocredit, minclass)
- [x] Prevención de reutilización de passwords (`pam_pwhistory`, `remember >= 5`)
- [x] Bloqueo de cuenta por intentos fallidos (`pam_faillock`: deny, unlock_time, fail_interval)
- [x] Orden correcto de módulos PAM (faillock antes de pam_unix)
- [x] Expiración de passwords configurada (maxdays, mindays, warndays)

### Fase 5: Checks de red y firewall (NET) ✅

- [x] Firewall activo (iptables/nftables/ufw)
- [x] Puertos abiertos innecesarios (comparar contra whitelist configurable)
- [x] IP forwarding deshabilitado (si no es router/gateway)
- [x] Servicios escuchando en 0.0.0.0 vs localhost
- [x] DNS resolvers configurados
- [x] DNSSEC validación habilitada (si corre resolver)
- [x] DNS over TLS/HTTPS (systemd-resolved, unbound)
- [x] IPv6 — deshabilitado o correctamente configurado
- [x] SNMP v1/v2c deshabilitado (solo SNMPv3 si es necesario)
- [x] Community strings default removidos (no `public`/`private`)
- [x] SNMP removido si no se usa

### Fase 6: Checks de servicios y procesos (SVC) ✅

- [x] Servicios innecesarios corriendo (telnet, rsh, rlogin, xinetd, etc.)
- [x] SSH: versión de protocolo, ciphers débiles, timeout configurado
- [x] NTP/chrony sincronizado y configurado (no solo corriendo)
- [x] NTP daemon no corriendo como root (user `_chrony` o `chrony`)
- [x] NTS (Network Time Security) habilitado si es posible
- [x] Fuentes de tiempo son confiables/autoritativas
- [x] Servicios críticos activos (sshd, fail2ban/crowdsec, logging)
- [x] Procesos corriendo como root que no deberían
- [x] MTA configurado como local-only (Postfix: `inet_interfaces = loopback-only`)
- [x] MTA no es open relay
- [x] Mail aliases para root (forward a cuenta monitoreada)
- [x] GDM/desktop environment no instalado en servidores
- [x] Automount deshabilitado (autofs)

### Fase 7: Checks de filesystem y permisos (FS) ✅

- [x] Archivos con SUID/SGID innecesarios
- [x] Archivos world-writable fuera de /tmp
- [x] Directorios sin sticky bit donde debería haber (/tmp, /var/tmp)
- [x] Particiones sensibles montadas con `noexec`, `nosuid`, `nodev`
- [x] `/dev/shm` montado con `nodev`, `nosuid`, `noexec`
- [x] Permisos de home directories (no world-readable)
- [x] Archivos sin dueño (orphaned files)
- [x] Particiones separadas: `/tmp`, `/var`, `/var/log`, `/var/log/audit`, `/var/tmp`, `/home`
- [x] `/tmp` en partición separada o tmpfs con `nodev`, `nosuid`, `noexec`
- [x] `/var/tmp` con `nodev`, `nosuid`, `noexec`
- [x] `tmp.mount` habilitado si usa systemd
- [x] Limpieza de temporales configurada (`systemd-tmpfiles` o `tmpreaper`)

### Fase 8: Checks de logging y auditoría (LOG) ✅

- [x] Syslog/journald activo y configurado
- [x] auditd instalado y corriendo
- [x] Reglas de audit para archivos sensibles (/etc/passwd, /etc/shadow, sudoers)
- [x] Rotación de logs configurada (logrotate)
- [x] Logs no son world-readable
- [x] AIDE o equivalente instalado (file integrity monitoring)
- [x] Base de datos AIDE inicializada
- [x] Checks de AIDE programados vía cron
- [x] AIDE cubre rutas críticas (`/bin`, `/sbin`, `/lib`, `/etc`, `/boot`)

### Fase 9: Checks de actualizaciones y paquetes (PKG) ✅

- [x] Paquetes con actualizaciones de seguridad pendientes
- [x] Repos configurados correctamente (no repos inseguros/HTTP)
- [x] Kernel actualizado
- [x] Automatic security updates habilitado (unattended-upgrades / dnf-automatic)

### Fase 10: Checks de hardening del kernel (HARD) ✅

- [x] Banner de login configurado (`/etc/issue`, `/etc/issue.net`)
- [x] Core dumps deshabilitados (sysctl + limits.conf `hard core 0`)
- [x] ASLR habilitado (`kernel.randomize_va_space = 2`)
- [x] Restricción de dmesg (`kernel.dmesg_restrict = 1`)
- [x] Restricción de ptrace (`kernel.yama.ptrace_scope >= 1`)
- [x] `/proc` hardening
- [x] Swap cifrado o ausente si no es necesario
- [x] Módulos de kernel innecesarios blacklisted (`cramfs`, `freevxfs`, `hfs`, `hfsplus`, `jffs2`, `squashfs`, `udf`)
- [x] USB storage deshabilitado si no se necesita (`usb-storage` blacklisted)
- [x] Módulos wireless deshabilitados si no se necesitan
- [x] Firewire/Thunderbolt DMA deshabilitado (`firewire-core`, `thunderbolt`)
- [x] Bluetooth deshabilitado si no se necesita

### Fase 11: Checks de boot y MAC (BOOT) ✅

- [x] Password de GRUB configurado
- [x] Permisos de config del bootloader (`/boot/grub/grub.cfg` = `0600` root:root)
- [x] Secure Boot habilitado si el hardware lo soporta
- [x] Single-user mode requiere autenticación
- [x] SELinux o AppArmor instalado y habilitado
- [x] SELinux en modo `Enforcing` / AppArmor en modo `enforce`
- [x] Sin perfiles/procesos unconfined
- [x] Verificar denials en logs de SELinux/AppArmor

### Fase 12: Checks de cron y jobs programados (CRON) ✅

- [x] Cron daemon habilitado y corriendo
- [x] Permisos de `/etc/crontab` = `0600` root:root
- [x] Permisos de directorios cron (`/etc/cron.{hourly,daily,weekly,monthly}` = `0700`)
- [x] `/etc/cron.allow` existe y `/etc/cron.deny` removido (whitelist)
- [x] `/etc/at.allow` existe y `/etc/at.deny` removido (whitelist)
- [x] Revisión de cron jobs sospechosos (descargas de red, scripts world-writable)
- [x] Auditoría de crontabs de usuarios

### Fase 13: Checks de TLS/SSL y criptografía (CRYPTO) ✅

- [x] Política criptográfica del sistema (no `LEGACY` en RHEL/Fedora)
- [x] Certificados expirados o próximos a expirar en `/etc/ssl/certs`, `/etc/pki`
- [x] Certificados self-signed en producción
- [x] TLS 1.0 y 1.1 deshabilitados system-wide
- [x] Cipher suites débiles (RC4, DES, 3DES, NULL)
- [x] Cadena de certificados completa
- [x] Permisos de claves privadas (`0600` o `0400`, owned by root o service user)
- [x] FIPS mode si es requerido
- [x] No uso de MD5/SHA1 en contextos de autenticación o firma

### Fase 14: Checks de secretos y credenciales (SECRETS) ✅

- [x] No secretos en variables de entorno (`/etc/environment`, `/etc/profile.d/`, `.bashrc`)
- [x] No passwords en shell history (`.bash_history`)
- [x] No credenciales en archivos world-readable
- [x] Permisos de archivos de credenciales (`.pgpass`, `.my.cnf`, `.netrc` = `0600`)

### Fase 15: Checks de containers (CONTAINER) ✅

- [x] Detectar si Docker/Podman está instalado
- [x] Config de Docker daemon (`/etc/docker/daemon.json`)
- [x] Permisos de Docker socket (`/var/run/docker.sock`)
- [x] Containers corriendo como root
- [x] Containers privilegiados (`--privileged`)
- [x] Límites de recursos en containers (CPU, memoria)
- [x] Docker content trust habilitado
- [x] ICC (Inter-container communication) deshabilitado si no se necesita
- [x] Read-only root filesystem en containers
- [x] Docker logging driver configurado
- [x] Imágenes de registries confiables

### Fase 16: Checks de resource limits (RLIMIT) ✅

- [x] Límite de archivos abiertos (open files) razonable
- [x] Límite de procesos por usuario (`nproc`) contra fork bombs
- [x] Límites de stack size
- [x] `/etc/security/limits.conf` sin entradas wildcard unlimited
- [x] Espacio en disco root filesystem (alerta >85%)
- [x] Espacio en `/var`, `/var/log`, `/tmp`
- [x] Inodes — verificar que no hay exhaustion

### Fase 17: Checks de NFS/SMB y filesystems de red (NFS) ✅

- [x] NFS exports revisados (no world-exported, `root_squash` habilitado)
- [x] NFSv3 deshabilitado si NFSv4 disponible
- [x] Samba config revisada (no guest access)
- [x] `rpcbind` deshabilitado si NFS no se usa

### Fase 18: Checks de rootkits y malware (MALWARE) ✅

- [x] rkhunter o chkrootkit instalado
- [x] Scans de rootkit programados vía cron
- [x] ClamAV instalado si el servidor maneja uploads o mail
- [x] Definiciones de antimalware actualizadas

### Fase 19: Checks de backups (BACKUP) ✅

- [x] Schedule de backup existe y se ejecutó recientemente
- [x] Backups cifrados
- [x] Permisos de archivos de backup (no world-readable)
- [x] Backup off-site/off-host (no solo en el mismo servidor)

### Fase 20: Output y reportes ✅

- [x] Output por consola con severidad
- [x] Output por consola con colores ANSI
- [x] `--format json` para integración con pipelines
- [x] `--format yaml`
- [x] `--output <file>` exportar a archivo
- [x] Resumen final: total checks, pass, warn, fail
- [x] Exit code basado en severidad (0 = todo OK, 1 = warnings, 2 = fails)
- [x] Recomendaciones de remediación por cada check fallido

### Fase 21: Configuración ✅

- [x] Config file (`/etc/infraudit/config.json` o `~/.infraudit.json`)
- [x] Whitelist de puertos permitidos
- [x] Whitelist de servicios permitidos como root
- [x] Skip de checks individuales o categorías (`--skip`)
- [x] Perfiles predefinidos: `web-server`, `db-server`, `minimal`, `container-host`
- [x] `--profile <nombre>` para seleccionar perfil

## Categorías de checks

| Categoría | Prefijo | Descripción |
|-----------|---------|-------------|
| `auth` | AUTH- | Usuarios, SSH, sudoers, passwords |
| `pam` | PAM- | PAM, calidad de passwords, lockout |
| `network` | NET- | Firewall, puertos, interfaces, DNS, SNMP |
| `services` | SVC- | Servicios, procesos, daemons, NTP, MTA |
| `filesystem` | FS- | Permisos, SUID, particiones, ownership, /tmp, /dev/shm |
| `logging` | LOG- | Syslog, auditd, rotación, AIDE/integrity |
| `packages` | PKG- | Actualizaciones, repos, kernel |
| `hardening` | HARD- | Kernel params, ASLR, ptrace, core dumps, módulos |
| `boot` | BOOT- | GRUB, Secure Boot, SELinux/AppArmor |
| `cron` | CRON- | Cron/at jobs, permisos, whitelist |
| `crypto` | CRYPTO- | TLS/SSL, certificados, ciphers, FIPS |
| `secrets` | SEC- | Credenciales expuestas, history, env vars |
| `container` | CTR- | Docker/Podman, imágenes, runtime security |
| `rlimit` | RLIM- | Resource limits, disco, inodes |
| `nfs` | NFS- | NFS exports, Samba, rpcbind |
| `malware` | MAL- | Rootkits, antimalware, integrity |
| `backup` | BAK- | Backups, cifrado, off-site |

## Modelo de severidad

| Nivel | Significado |
|-------|-------------|
| `CRITICAL` | Vulnerabilidad explotable, acción inmediata |
| `HIGH` | Riesgo significativo, corregir pronto |
| `MEDIUM` | Buena práctica no aplicada |
| `LOW` | Mejora recomendada, bajo riesgo |
| `INFO` | Informativo, sin acción necesaria |

## Estructura del proyecto

```
infraudit/
├── .claude/commands/       # Skills de Claude Code
├── docs/                   # Documentación
├── cmd/
│   ├── root.go             # Comando raíz
│   ├── audit.go            # Subcomando audit
│   └── list.go             # Subcomando list
├── internal/
│   ├── version/            # Info de versión
│   ├── check/              # Interfaz Check, Result, Registry
│   ├── checks/
│   │   ├── auth/           # AUTH- checks
│   │   ├── pam/            # PAM- checks
│   │   ├── network/        # NET- checks
│   │   ├── services/       # SVC- checks
│   │   ├── filesystem/     # FS- checks
│   │   ├── logging/        # LOG- checks
│   │   ├── packages/       # PKG- checks
│   │   ├── hardening/      # HARD- checks
│   │   ├── boot/           # BOOT- checks
│   │   ├── cron/           # CRON- checks
│   │   ├── crypto/         # CRYPTO- checks
│   │   ├── secrets/        # SEC- checks
│   │   ├── container/      # CTR- checks
│   │   ├── rlimit/         # RLIM- checks
│   │   ├── nfs/            # NFS- checks
│   │   ├── malware/        # MAL- checks
│   │   └── backup/         # BAK- checks
│   └── report/             # Formateo y output de reportes
├── main.go
├── go.mod / go.sum
├── PLAN.md
└── README.md
```
