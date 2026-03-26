Run the infraudit project tests.

Run:
1. `export PATH=$HOME/.local/go/bin:$PATH`
2. `go test ./...` in the project directory
3. `go vet ./...`
4. `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run`
5. Report results: passed, failed, and coverage if available.

If there are test or lint failures, fix them before continuing.
