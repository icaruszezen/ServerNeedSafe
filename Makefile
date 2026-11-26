.PHONY: all web server windows test clean docker

SNS_VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null || echo dev)
SNS_COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "")
SNS_BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION_PKG := github.com/icaruszezen/ServerNeedSafe/internal/version
LDFLAGS := -s -w -X $(VERSION_PKG).Version=$(SNS_VERSION) -X $(VERSION_PKG).Commit=$(SNS_COMMIT) -X $(VERSION_PKG).BuildTime=$(SNS_BUILD_TIME)

all: web server windows

web:
	cd web && npm ci --no-audit --no-fund && npm run build

server: web
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/sns-server-linux-amd64 ./cmd/server

windows: web
	mkdir -p dist
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS) -H windowsgui" -o dist/ServerNeedSafe-windows-amd64.exe ./cmd/desktop
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS) -H windowsgui" -o dist/ServerNeedSafe-windows-arm64.exe ./cmd/desktop

test: web
	go vet ./...
	go test ./... -v -race -count=1

docker:
	docker compose up -d --build

clean:
	rm -rf dist web/dist
