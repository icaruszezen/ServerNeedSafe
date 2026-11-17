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
	dataDir := flag.String("data-dir", defaultDataDir, "零知识盲密文容器持久化目录")
	ttlStr := flag.String("session-ttl", defaultTTL, "单次零知识认证会话最长有效期")
	flag.Parse()

	sessionTTL, err := time.ParseDuration(*ttlStr)
	if err != nil || sessionTTL <= 0 {
		sessionTTL = 8 * time.Hour
	}

	vaultPath := filepath.Join(*dataDir, "vault.sns")
	blindStore, err := vault.NewBlindStore(vaultPath)
	if err != nil {
		log.Fatalf("[ServerNeedSafe] 初始化零知识盲密文存储失败: %v", err)
	}

	authMgr, err := auth.NewManager(sessionTTL, false)
	if err != nil {
		log.Fatalf("[ServerNeedSafe] 初始化零知识挑战认证引擎失败: %v", err)
	}

	relayMgr := relay.NewManager(*addr)

	staticFS, err := web.DistFS()
	if err != nil {
		log.Fatalf("[ServerNeedSafe] 加载内置 Web + WASM 静态资源失败: %v", err)
	}

	apiServer := api.NewServer(api.Config{
		DeployMode: "server",
		BlindStore: blindStore,
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
		fmt.Printf("  ServerNeedSafe — 多服务器安全管理与零知识加密终端 (Zero-Knowledge)\n")
		fmt.Printf("  监听地址: http://%s\n", *addr)
		fmt.Printf("  盲密文包: %s\n", vaultPath)
		fmt.Printf("  隔离架构: 客户端 WASM E2EE (Argon2id + XChaCha20-Poly1305 + Ed25519)\n")
		fmt.Printf("  安全保证: 服务端零密码 · 零主密钥 · 零明文（抗服务器 root 泄露）\n")
		fmt.Printf("====================================================================\n")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[ServerNeedSafe] HTTP 服务异常退出: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("[ServerNeedSafe] 收到停止信号，正在注销全部会话并关闭加密 TCP 中继流...")
	authMgr.RevokeAll()
	apiServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}
