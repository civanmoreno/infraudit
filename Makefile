BINARY   := infraudit
VERSION  := $(shell grep 'Version =' internal/version/version.go | cut -d'"' -f2)
LDFLAGS  := -s -w

.PHONY: build test lint vet clean release cover docker

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BINARY) .

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY) dist/*

release: clean
	mkdir -p dist
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 .
	cd dist && sha256sum $(BINARY)-* > checksums.txt

cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

docker:
	docker build -t $(BINARY):$(VERSION) .
