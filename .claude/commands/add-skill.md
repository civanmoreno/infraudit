Add a new skill (subcommand) to infraudit.

Ask the user for the skill name and what it should do. Then:

1. Create a feature branch: `git checkout -b feature/<name>`
2. Create `cmd/<name>.go` with the cobra subcommand registered in `rootCmd`
3. If the logic is complex, create `internal/<name>/` with the implementation
4. Create `cmd/<name>_test.go` with unit tests
5. Run `go build -o infraudit .` and verify with `./infraudit <name> --help`
6. Run `go test ./...`
7. Run `go vet ./...`
8. Run `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run`
9. Fix any lint or test failures before continuing
10. Update `PLAN.md` and `docs/roadmap.html` marking the skill as implemented
11. Update relevant docs in `docs/` (getting-started.html, output.html, etc.)
12. Commit with a descriptive message including a test plan section:
    ```
    feat: add <name> command

    Description of what the command does.

    Test plan:
    - [x] go build compiles
    - [x] go test ./... passes
    - [x] golangci-lint run — 0 issues
    - [x] Manual verification of command output
    ```
13. Push and create PR with test plan in the PR body
