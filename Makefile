.PHONY: all web server windows test clean docker

all: web server windows

web:
	cd web && npm ci --no-audit --no-fund && npm run build

server: web
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/sns-server-linux-amd64 ./cmd/server

windows: web
	mkdir -p dist
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -H windowsgui" -o dist/ServerNeedSafe-windows-amd64.exe ./cmd/desktop
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -trimpath -ldflags="-s -w -H windowsgui" -o dist/ServerNeedSafe-windows-arm64.exe ./cmd/desktop

test:
	go test ./internal/... -v -race

docker:
	docker compose up -d --build

clean:
	rm -rf dist web/dist
