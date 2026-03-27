# Security Policy

## Versiones Soportadas

| Version | Soportada |
|---------|-----------|
| 2.x     | Si        |
| < 2.0   | No        |

## Reportar una Vulnerabilidad

infraudit es una herramienta de auditoría de seguridad que se ejecuta con privilegios elevados e inspecciona configuraciones sensibles del sistema. Nos tomamos la seguridad muy en serio.

**No abras un issue público.** En su lugar:

1. Envía un email a **security@infraudit.com** con:
   - Descripción de la vulnerabilidad
   - Pasos para reproducir
   - Versión(es) afectada(s)
   - Impacto potencial

2. Recibirás una respuesta dentro de **48 horas**.

3. Trabajaremos contigo para:
   - Confirmar la vulnerabilidad
   - Desarrollar un fix
   - Coordinar la divulgación

## Proceso de Divulgación

Seguimos una política de divulgación responsable:

1. El reporte se recibe y se confirma (48h)
2. Se desarrolla y testea un fix (1-7 días según severidad)
3. Se publica un release con el fix
4. Se publica un advisory de seguridad en GitHub
5. Se da crédito al reportador (si lo desea)

## Alcance

Los siguientes tipos de hallazgos son relevantes:

- Ejecución de comandos arbitrarios a través de inputs maliciosos (YAML plugins, config files)
- Path traversal en la lectura de archivos
- Inyección de comandos en checks que ejecutan comandos del sistema
- Bypass de validaciones de seguridad
- Exposición de información sensible en reportes o logs
- Vulnerabilidades en dependencias

## Fuera de Alcance

- Hallazgos que requieren acceso root previo (infraudit ya se ejecuta como root)
- Falsos positivos o falsos negativos en checks de auditoría (reportar como issue regular)
- Vulnerabilidades en sistemas operativos o herramientas que infraudit inspecciona
