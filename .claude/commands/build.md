Build the infraudit project.

Run:
1. `export PATH=$HOME/.local/go/bin:$PATH`
2. `go build -o infraudit .` in the project directory
3. `go vet ./...`
4. `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run`
5. Verify the binary was created with `./infraudit --version`

If there are compilation or lint errors, fix them before continuing.
