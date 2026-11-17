//go:build !windows

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/api"
	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/relay"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/icaruszezen/ServerNeedSafe/web"
)

func main() {
	dataDir := os.Getenv("SNS_DATA_DIR")
	if dataDir == "" {
		dataDir = "./data-local"
	}
	vaultPath := filepath.Join(dataDir, "vault.sns")
	blindStore, err := vault.NewBlindStore(vaultPath)
	if err != nil {
		log.Fatalf("init blind vault: %v", err)
	}

	authMgr, err := auth.NewManager(12*time.Hour, true)
	if err != nil {
		log.Fatalf("init auth: %v", err)
	}

	staticFS, err := web.DistFS()
	if err != nil {
		log.Fatalf("load dist: %v", err)
	}

	addr := os.Getenv("SNS_DESKTOP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen loopback: %v", err)
	}

	relayMgr := relay.NewManager(ln.Addr().String())
	apiServer := api.NewServer(api.Config{
		DeployMode: "desktop",
		BlindStore: blindStore,
		Auth:       authMgr,
		Relay:      relayMgr,
		StaticFS:   staticFS,
	})

	httpServer := &http.Server{
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	port := ln.Addr().(*net.TCPAddr).Port
	bootURL := fmt.Sprintf("http://127.0.0.1:%d/__desktop_boot?boot=%s", port, authMgr.DesktopBootCode())
	fmt.Printf("[ServerNeedSafe Zero-Knowledge Local Mode] Loopback URL: %s\n", bootURL)

	go func() {
		_ = httpServer.Serve(ln)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	authMgr.RevokeAll()
	apiServer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}
