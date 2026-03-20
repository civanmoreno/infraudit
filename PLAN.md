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

### Fase 2: Motor de auditoría y modelo de checks

- [ ] Definir interfaz `Check` (nombre, categoría, severidad, `Run() Result`)
- [ ] Registry de checks con autodiscovery
- [ ] Modelo de resultado: PASS / WARN / FAIL / ERROR con mensaje y remediación
- [ ] `infraudit audit` — ejecuta todos los checks registrados
- [ ] `infraudit audit --category <cat>` — filtra por categoría
- [ ] `infraudit list` — lista todos los checks disponibles

### Fase 3: Checks de usuarios y autenticación (AUTH)

- [ ] Root login por SSH deshabilitado (`PermitRootLogin no`)
- [ ] Autenticación por password SSH deshabilitada (`PasswordAuthentication no`)
- [ ] Usuarios con UID 0 (solo root debe tenerlo)
- [ ] Usuarios sin password o con password vacío
- [ ] Cuentas del sistema con shell de login (deben tener `/nologin` o `/false`)
- [ ] Archivo sudoers: uso de `NOPASSWD` excesivo
- [ ] Permisos de `/etc/passwd`, `/etc/shadow`, `/etc/group`
- [ ] Restricción de `su` vía `pam_wheel.so` (solo grupo autorizado)

### Fase 4: Checks de PAM y políticas de contraseñas (PAM)

- [ ] Calidad de passwords vía `pam_pwquality` (minlen, dcredit, ucredit, lcredit, ocredit, minclass)
- [ ] Prevención de reutilización de passwords (`pam_pwhistory`, `remember >= 5`)
- [ ] Bloqueo de cuenta por intentos fallidos (`pam_faillock`: deny, unlock_time, fail_interval)
- [ ] Orden correcto de módulos PAM (faillock antes de pam_unix)
- [ ] Expiración de passwords configurada (maxdays, mindays, warndays)

### Fase 5: Checks de red y firewall (NET)

- [ ] Firewall activo (iptables/nftables/ufw)
- [ ] Puertos abiertos innecesarios (comparar contra whitelist configurable)
- [ ] IP forwarding deshabilitado (si no es router/gateway)
- [ ] Servicios escuchando en 0.0.0.0 vs localhost
- [ ] DNS resolvers configurados
- [ ] DNSSEC validación habilitada (si corre resolver)
- [ ] DNS over TLS/HTTPS (systemd-resolved, unbound)
- [ ] IPv6 — deshabilitado o correctamente configurado
- [ ] SNMP v1/v2c deshabilitado (solo SNMPv3 si es necesario)
- [ ] Community strings default removidos (no `public`/`private`)
- [ ] SNMP removido si no se usa

### Fase 6: Checks de servicios y procesos (SVC)

- [ ] Servicios innecesarios corriendo (telnet, rsh, rlogin, xinetd, etc.)
- [ ] SSH: versión de protocolo, ciphers débiles, timeout configurado
- [ ] NTP/chrony sincronizado y configurado (no solo corriendo)
- [ ] NTP daemon no corriendo como root (user `_chrony` o `chrony`)
- [ ] NTS (Network Time Security) habilitado si es posible
- [ ] Fuentes de tiempo son confiables/autoritativas
- [ ] Servicios críticos activos (sshd, fail2ban/crowdsec, logging)
- [ ] Procesos corriendo como root que no deberían
- [ ] MTA configurado como local-only (Postfix: `inet_interfaces = loopback-only`)
- [ ] MTA no es open relay
- [ ] Mail aliases para root (forward a cuenta monitoreada)
- [ ] GDM/desktop environment no instalado en servidores
- [ ] Automount deshabilitado (autofs)

### Fase 7: Checks de filesystem y permisos (FS)

- [ ] Archivos con SUID/SGID innecesarios
- [ ] Archivos world-writable fuera de /tmp
- [ ] Directorios sin sticky bit donde debería haber (/tmp, /var/tmp)
- [ ] Particiones sensibles montadas con `noexec`, `nosuid`, `nodev`
- [ ] `/dev/shm` montado con `nodev`, `nosuid`, `noexec`
- [ ] Permisos de home directories (no world-readable)
- [ ] Archivos sin dueño (orphaned files)
- [ ] Particiones separadas: `/tmp`, `/var`, `/var/log`, `/var/log/audit`, `/var/tmp`, `/home`
- [ ] `/tmp` en partición separada o tmpfs con `nodev`, `nosuid`, `noexec`
- [ ] `/var/tmp` con `nodev`, `nosuid`, `noexec`
- [ ] `tmp.mount` habilitado si usa systemd
- [ ] Limpieza de temporales configurada (`systemd-tmpfiles` o `tmpreaper`)

### Fase 8: Checks de logging y auditoría (LOG)

- [ ] Syslog/journald activo y configurado
- [ ] auditd instalado y corriendo
- [ ] Reglas de audit para archivos sensibles (/etc/passwd, /etc/shadow, sudoers)
- [ ] Rotación de logs configurada (logrotate)
- [ ] Logs no son world-readable
- [ ] AIDE o equivalente instalado (file integrity monitoring)
- [ ] Base de datos AIDE inicializada
- [ ] Checks de AIDE programados vía cron
- [ ] AIDE cubre rutas críticas (`/bin`, `/sbin`, `/lib`, `/etc`, `/boot`)

### Fase 9: Checks de actualizaciones y paquetes (PKG)

- [ ] Paquetes con actualizaciones de seguridad pendientes
- [ ] Repos configurados correctamente (no repos inseguros/HTTP)
- [ ] Kernel actualizado
- [ ] Automatic security updates habilitado (unattended-upgrades / dnf-automatic)

### Fase 10: Checks de hardening del kernel (HARD)

- [ ] Banner de login configurado (`/etc/issue`, `/etc/issue.net`)
- [ ] Core dumps deshabilitados (sysctl + limits.conf `hard core 0`)
- [ ] ASLR habilitado (`kernel.randomize_va_space = 2`)
- [ ] Restricción de dmesg (`kernel.dmesg_restrict = 1`)
- [ ] Restricción de ptrace (`kernel.yama.ptrace_scope >= 1`)
- [ ] `/proc` hardening
- [ ] Swap cifrado o ausente si no es necesario
- [ ] Módulos de kernel innecesarios blacklisted (`cramfs`, `freevxfs`, `hfs`, `hfsplus`, `jffs2`, `squashfs`, `udf`)
- [ ] USB storage deshabilitado si no se necesita (`usb-storage` blacklisted)
- [ ] Módulos wireless deshabilitados si no se necesitan
- [ ] Firewire/Thunderbolt DMA deshabilitado (`firewire-core`, `thunderbolt`)
- [ ] Bluetooth deshabilitado si no se necesita

### Fase 11: Checks de boot y MAC (BOOT)

- [ ] Password de GRUB configurado
- [ ] Permisos de config del bootloader (`/boot/grub/grub.cfg` = `0600` root:root)
- [ ] Secure Boot habilitado si el hardware lo soporta
- [ ] Single-user mode requiere autenticación
- [ ] SELinux o AppArmor instalado y habilitado
- [ ] SELinux en modo `Enforcing` / AppArmor en modo `enforce`
- [ ] Sin perfiles/procesos unconfined
- [ ] Verificar denials en logs de SELinux/AppArmor

### Fase 12: Checks de cron y jobs programados (CRON)

- [ ] Cron daemon habilitado y corriendo
- [ ] Permisos de `/etc/crontab` = `0600` root:root
- [ ] Permisos de directorios cron (`/etc/cron.{hourly,daily,weekly,monthly}` = `0700`)
- [ ] `/etc/cron.allow` existe y `/etc/cron.deny` removido (whitelist)
- [ ] `/etc/at.allow` existe y `/etc/at.deny` removido (whitelist)
- [ ] Revisión de cron jobs sospechosos (descargas de red, scripts world-writable)
- [ ] Auditoría de crontabs de usuarios

### Fase 13: Checks de TLS/SSL y criptografía (CRYPTO)

- [ ] Política criptográfica del sistema (no `LEGACY` en RHEL/Fedora)
- [ ] Certificados expirados o próximos a expirar en `/etc/ssl/certs`, `/etc/pki`
- [ ] Certificados self-signed en producción
- [ ] TLS 1.0 y 1.1 deshabilitados system-wide
- [ ] Cipher suites débiles (RC4, DES, 3DES, NULL)
- [ ] Cadena de certificados completa
- [ ] Permisos de claves privadas (`0600` o `0400`, owned by root o service user)
- [ ] FIPS mode si es requerido
- [ ] No uso de MD5/SHA1 en contextos de autenticación o firma

### Fase 14: Checks de secretos y credenciales (SECRETS)

- [ ] No secretos en variables de entorno (`/etc/environment`, `/etc/profile.d/`, `.bashrc`)
- [ ] No passwords en shell history (`.bash_history`)
- [ ] No credenciales en archivos world-readable
- [ ] Permisos de archivos de credenciales (`.pgpass`, `.my.cnf`, `.netrc` = `0600`)

### Fase 15: Checks de containers (CONTAINER)

- [ ] Detectar si Docker/Podman está instalado
- [ ] Config de Docker daemon (`/etc/docker/daemon.json`)
- [ ] Permisos de Docker socket (`/var/run/docker.sock`)
- [ ] Containers corriendo como root
- [ ] Containers privilegiados (`--privileged`)
- [ ] Límites de recursos en containers (CPU, memoria)
- [ ] Docker content trust habilitado
- [ ] ICC (Inter-container communication) deshabilitado si no se necesita
- [ ] Read-only root filesystem en containers
- [ ] Docker logging driver configurado
- [ ] Imágenes de registries confiables

### Fase 16: Checks de resource limits (RLIMIT)

- [ ] Límite de archivos abiertos (open files) razonable
- [ ] Límite de procesos por usuario (`nproc`) contra fork bombs
- [ ] Límites de stack size
- [ ] `/etc/security/limits.conf` sin entradas wildcard unlimited
- [ ] Espacio en disco root filesystem (alerta >85%)
- [ ] Espacio en `/var`, `/var/log`, `/tmp`
- [ ] Inodes — verificar que no hay exhaustion

### Fase 17: Checks de NFS/SMB y filesystems de red (NFS)

- [ ] NFS exports revisados (no world-exported, `root_squash` habilitado)
- [ ] NFSv3 deshabilitado si NFSv4 disponible
- [ ] Samba config revisada (no guest access)
- [ ] `rpcbind` deshabilitado si NFS no se usa

### Fase 18: Checks de rootkits y malware (MALWARE)

- [ ] rkhunter o chkrootkit instalado
- [ ] Scans de rootkit programados vía cron
- [ ] ClamAV instalado si el servidor maneja uploads o mail
- [ ] Definiciones de antimalware actualizadas

### Fase 19: Checks de backups (BACKUP)

- [ ] Schedule de backup existe y se ejecutó recientemente
- [ ] Backups cifrados
- [ ] Permisos de archivos de backup (no world-readable)
- [ ] Backup off-site/off-host (no solo en el mismo servidor)

### Fase 20: Output y reportes

- [ ] Output por consola con colores y severidad
- [ ] `--format json` para integración con pipelines
- [ ] `--format yaml`
- [ ] `--output <file>` exportar a archivo
- [ ] Resumen final: total checks, pass, warn, fail por categoría
- [ ] Exit code basado en severidad (0 = todo OK, 1 = warnings, 2 = fails)
- [ ] Recomendaciones de remediación por cada check fallido

### Fase 21: Configuración

- [ ] Config file (`/etc/infraudit/config.yaml` o `~/.infraudit.yaml`)
- [ ] Whitelist de puertos permitidos
- [ ] Whitelist de servicios permitidos como root
- [ ] Skip de checks individuales o categorías
- [ ] Perfiles predefinidos: `web-server`, `db-server`, `minimal`, `container-host`
- [ ] `--profile <nombre>` para seleccionar perfil

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
