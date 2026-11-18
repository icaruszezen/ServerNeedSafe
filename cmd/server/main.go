package main

import (
	"context"
	"flag"
	"fmt"
	"log"
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

func envOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func main() {
	defaultAddr := envOrDefault("SNS_ADDR", "0.0.0.0:8080")
	defaultDataDir := envOrDefault("SNS_DATA_DIR", "./data")
	defaultTTL := envOrDefault("SNS_SESSION_TTL", "8h")

	addr := flag.String("addr", defaultAddr, "HTTP 监听地址 (例如 0.0.0.0:8080)")
	dataDir := flag.String("data-dir", defaultDataDir, "加密保险库与自动挂载密钥持久化目录")
	ttlStr := flag.String("session-ttl", defaultTTL, "Web 管理会话最长有效期")
	flag.Parse()

	sessionTTL, err := time.ParseDuration(*ttlStr)
	if err != nil || sessionTTL <= 0 {
		sessionTTL = 8 * time.Hour
	}

	vaultPath := filepath.Join(*dataDir, "vault.sns")
	blindStore, err := vault.NewBlindStore(vaultPath)
	if err != nil {
		log.Fatalf("[ServerNeedSafe] 初始化加密存储失败: %v", err)
	}

	authMgr, err := auth.NewManager(sessionTTL, false)
	if err != nil {
		log.Fatalf("[ServerNeedSafe] 初始化认证会话引擎失败: %v", err)
	}

	relayMgr := relay.NewManager(*addr)

	staticFS, err := web.DistFS()
	if err != nil {
		log.Fatalf("[ServerNeedSafe] 加载内置 Web 静态资源失败: %v", err)
	}

	keyMgr := vault.NewServerKeyManager(*dataDir)
	apiServer := api.NewServer(api.Config{
		DeployMode: "server",
		BlindStore: blindStore,
		KeyMgr:     keyMgr,
		Auth:       authMgr,
		Relay:      relayMgr,
		StaticFS:   staticFS,
	})

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		fmt.Printf("====================================================================\n")
		fmt.Printf("  ServerNeedSafe — 多服务器安全管理与 7×24 智能巡检守护引擎\n")
		fmt.Printf("  监听地址: http://%s\n", *addr)
		fmt.Printf("  加密存储: %s (XChaCha20-Poly1305 + Argon2id)\n", vaultPath)
		fmt.Printf("  自动挂载: %s (0600 守护进程密钥，重启 <1ms 自动恢复)\n", keyMgr.KeyPath())
		fmt.Printf("  后台能力: 7×24 SSH 状态监控 · AI 定时安全巡检 · 轻量极速 Web 控制台\n")
		fmt.Printf("====================================================================\n")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[ServerNeedSafe] HTTP 服务异常退出: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("[ServerNeedSafe] 收到停止信号，正在注销 Web 会话并安全停止 7×24 守护协程...")
	authMgr.RevokeAll()
	apiServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}
