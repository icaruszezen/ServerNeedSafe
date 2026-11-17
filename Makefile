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

test: web
	go vet ./...
	GOOS=js GOARCH=wasm go vet ./cmd/wasm ./internal/vault ./internal/sshmanager ./internal/zkclient
	go test ./... -v -race -count=1

docker:
	docker compose up -d --build

clean:
	rm -rf dist web/dist web/public/sns-zk.wasm.gz web/src/zk/wasm_exec.js web/src/zk/wasmIntegrity.json
