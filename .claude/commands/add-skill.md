Add a new skill (subcommand) to infraudit.

Ask the user for the skill name and what it should do. Then:

1. Create `cmd/<name>.go` with the cobra subcommand registered in `rootCmd`
2. If the logic is complex, create `internal/skills/<name>/` with the implementation
3. Update `PLAN.md` marking the skill as implemented or in progress
4. Build with `go build -o infraudit .` and verify with `./infraudit <name> --help`
