Add a new skill (subcommand) to infraudit.

Ask the user for the skill name and what it should do. Then:

1. Create `cmd/<name>.go` with the cobra subcommand registered in `rootCmd`
2. If the logic is complex, create `internal/skills/<name>/` with the implementation
3. Create `cmd/<name>_test.go` with unit tests
4. Run `go build -o infraudit .` and verify with `./infraudit <name> --help`
5. Run `go test ./...`
6. Run `go vet ./...`
7. Run `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run`
8. Fix any lint or test failures before continuing
9. Update `PLAN.md` and `docs/roadmap.html` marking the skill as implemented
