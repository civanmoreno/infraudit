Agregar un nuevo skill (subcomando) a infraudit.

Pedí al usuario el nombre del skill y qué debe hacer. Luego:

1. Creá `cmd/<nombre>.go` con el subcomando cobra registrado en `rootCmd`
2. Si la lógica es compleja, creá `internal/skills/<nombre>/` con la implementación
3. Actualizá `PLAN.md` marcando el skill como implementado o en progreso
4. Compilá con `go build -o infraudit .` y verificá con `./infraudit <nombre> --help`
