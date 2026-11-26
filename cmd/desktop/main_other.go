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
	"syscall"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/api"
	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/updater"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/icaruszezen/ServerNeedSafe/internal/version"
	"github.com/icaruszezen/ServerNeedSafe/web"
)

type restartRequest struct {
	exePath    string
	backupPath string
}

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-version" || arg == "-v" {
			fmt.Println(version.String())
			return
		}
	}

	updater.CleanupPreviousBackup()

	dataDir := os.Getenv("SNS_DATA_DIR")
	if dataDir == "" {
		dataDir = "./data-local"
	}
	store, err := vault.NewStore(dataDir)
	if err != nil {
		log.Fatalf("init store: %v", err)
	}

	authMgr, err := auth.NewManager(auth.DefaultSessionTTL, true)
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

	restartCh := make(chan restartRequest, 1)

	apiServer := api.NewServer(api.Config{
		DeployMode: "desktop",
		Store:      store,
		Auth:       authMgr,
		StaticFS:   staticFS,
		OnRestart: func(exePath, backupPath string) error {
			select {
			case restartCh <- restartRequest{exePath: exePath, backupPath: backupPath}:
				return nil
			default:
				return fmt.Errorf("重启指令已在队列中")
			}
		},
	})

	httpServer := &http.Server{
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	port := ln.Addr().(*net.TCPAddr).Port
	bootURL := fmt.Sprintf("http://127.0.0.1:%d/__desktop_boot?boot=%s", port, authMgr.DesktopBootCode())
	fmt.Printf("[ServerNeedSafe Local Desktop Mode %s] Loopback URL: %s\n", version.Current().Version, bootURL)

	go func() {
		_ = httpServer.Serve(ln)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigCh:
		authMgr.RevokeAll()
		apiServer.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	case req := <-restartCh:
		authMgr.RevokeAll()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = httpServer.Shutdown(ctx)
		cancel()
		apiServer.Close()
		if err := updater.ReexecCurrentProcess(req.exePath, os.Args, os.Environ()); err != nil {
			_ = updater.RestoreBinaryBackup(req.exePath, req.backupPath)
			log.Fatalf("reexec after update failed: %v", err)
		}
	}
}
