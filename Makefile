BINARY  := transfermapexec
DIST    := dist
LDFLAGS := -s -w
GOFLAGS := -trimpath
# CGO is disabled so every target is a pure-Go static binary (none of the dependencies needs cgo).
export CGO_ENABLED = 0

.PHONY: build native tidy vet clean \
        linux-amd64 linux-arm64 windows-amd64 darwin-arm64 darwin-amd64

## build: compile all release targets into ./dist
build: linux-amd64 linux-arm64 windows-amd64 darwin-arm64 darwin-amd64
	@echo "All builds complete -> $(DIST)/"

linux-amd64:
	@mkdir -p $(DIST)
	GOOS=linux   GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-amd64 .

linux-arm64:
	@mkdir -p $(DIST)
	GOOS=linux   GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-arm64 .

windows-amd64:
	@mkdir -p $(DIST)
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-windows-amd64.exe .

darwin-arm64:
	@mkdir -p $(DIST)
	GOOS=darwin  GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-darwin-arm64 .

darwin-amd64:
	@mkdir -p $(DIST)
	GOOS=darwin  GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-darwin-amd64 .

## native: build a binary for the current machine (./transfermapexec)
native:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) .

## tidy: sync go.mod / go.sum
tidy:
	go mod tidy

## vet: run go vet
vet:
	go vet ./...

## clean: remove build artifacts
clean:
	rm -rf $(DIST) $(BINARY)
