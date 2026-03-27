# Contribuir a infraudit

Gracias por tu interés en contribuir. Este documento explica cómo hacerlo.

## Formas de Contribuir

- **Reportar bugs** — Abre un issue usando la plantilla de bug report
- **Proponer checks nuevos** — Abre un issue usando la plantilla de nuevo check
- **Crear plugins YAML** — Comparte tus checks personalizados
- **Mejorar documentación** — Correcciones, traducciones, ejemplos
- **Enviar código** — Bug fixes, nuevos checks, mejoras

## Requisitos Previos

- Go 1.24+
- golangci-lint v2
- Familiaridad con CIS Benchmarks o estándares de seguridad Linux

## Configuración del Entorno

```bash
git clone https://github.com/civanmoreno/infraudit.git
cd infraudit
make build    # Compilar
make test     # Ejecutar tests
make lint     # Ejecutar linter
```

## Proceso para Pull Requests

1. **Fork** el repositorio
2. **Crea un branch** desde `main`: `git checkout -b feature/mi-cambio`
3. **Haz tus cambios** siguiendo las convenciones de código
4. **Ejecuta tests y lint:**
   ```bash
   make test
   make lint
   ```
5. **Commit** con un mensaje descriptivo (ver convenciones abajo)
6. **Push** a tu fork y abre un Pull Request

### Convenciones de Commits

Usamos commits convencionales:

```
feat: agregar check para validar configuración de Redis
fix: corregir falso positivo en AUTH-007 cuando shadow no existe
docs: actualizar documentación de plugins
test: agregar tests para checks de logging
refactor: consolidar parsers de sysctl
```

Prefijos válidos: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`

## Agregar un Check Nuevo

### Check Built-in (Go)

1. Crea un archivo en `internal/checks/<categoría>/`
2. Implementa la interfaz `check.Check`:

```go
package auth

import "github.com/civanmoreno/infraudit/internal/check"

func init() {
    check.Register(&myCheck{})
}

type myCheck struct{}

func (c *myCheck) ID() string               { return "AUTH-XXX" }
func (c *myCheck) Name() string             { return "Descripción corta" }
func (c *myCheck) Category() string         { return "auth" }
func (c *myCheck) Severity() check.Severity { return check.High }
func (c *myCheck) Description() string      { return "Qué valida este check" }

func (c *myCheck) Run() check.Result {
    // Lógica del check
    return check.Result{
        Status:      check.Pass,
        Message:     "Todo bien",
    }
}
```

3. Si el check depende de systemd, agrega:
```go
func (c *myCheck) RequiredInit() string { return "systemd" }
```

4. Si el check es específico de una distro:
```go
func (c *myCheck) SupportedOS() []string { return []string{"debian"} }
```

5. Usa `check.P(path)` para resolver rutas de archivos (permite testing con FSRoot)
6. Agrega tests en `<categoría>/<categoría>_test.go`
7. Agrega el mapeo CIS en `internal/compliance/cis.go` si aplica

### Check como Plugin (YAML)

Crea un archivo en `/etc/infraudit/checks.d/`:

```yaml
id: CUSTOM-001
name: Mi check personalizado
category: custom
severity: medium
description: Qué valida
remediation: Cómo arreglarlo
rule:
  type: file_contains
  path: /etc/mi-app/config
  pattern: "secure=true"
```

Ver [documentación de plugins](https://civanmoreno.github.io/infraudit/configuration.html) para todos los tipos de regla.

## Convenciones de Código

- **Formato:** `gofmt` (se valida en CI)
- **Linting:** `golangci-lint` con la configuración del proyecto (`.golangci.yml`)
- **Tests:** Ejecutar con `-race` flag. Usar `check.FSRoot` para tests de checks que leen archivos.
- **Errores:** Retornar `check.Error` con mensaje claro cuando un check no puede ejecutarse. No usar `panic`.
- **Permisos en tests:** Usar `//nolint:gosec` cuando se necesiten permisos amplios en archivos de test.
- **Sin dependencias nuevas** a menos que sea estrictamente necesario. infraudit es deliberadamente minimal.

## IDs de Checks

| Categoría | Prefijo | Rango actual |
|-----------|---------|-------------|
| auth | AUTH- | 001-022 |
| pam | PAM- | 001-013 |
| network | NET- | 001-035 |
| services | SVC- | 001-056 |
| filesystem | FS- | 001-035 |
| logging | LOG- | 001-035 |
| packages | PKG- | 001-004 |
| hardening | HARD- | 001-026 |
| boot | BOOT- | 001-008 |
| cron | CRON- | 001-007 |
| crypto | CRYPTO- | 001-009 |
| secrets | SEC- | 001-004 |
| container | CTR- | 001-011 |
| rlimit | RLIM- | 001-007 |
| nfs | NFS- | 001-004 |
| malware | MAL- | 001-004 |
| backup | BAK- | 001-004 |

Al agregar un check nuevo, usa el siguiente número disponible en la categoría correspondiente.

## Reportar Vulnerabilidades

Ver [SECURITY.md](SECURITY.md) para el proceso de reporte de vulnerabilidades. **No abras issues públicos para vulnerabilidades.**

## Licencia

Al contribuir, aceptas que tus contribuciones se licencian bajo los mismos términos que el proyecto ([BSL 1.1](LICENSE)).
