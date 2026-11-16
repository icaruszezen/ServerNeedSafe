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
	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
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
	dataDir := flag.String("data-dir", defaultDataDir, "加密数据包持久化目录")
	ttlStr := flag.String("session-ttl", defaultTTL, "单次登录会话最长有效期")
	flag.Parse()

	sessionTTL, err := time.ParseDuration(*ttlStr)
	if err != nil || sessionTTL <= 0 {
		sessionTTL = 8 * time.Hour
	}

	vaultPath := filepath.Join(*dataDir, "vault.sns")
	store, err := vault.NewStore(vaultPath)
	if err != nil {
		log.Fatalf("[ServerNeedSafe] 初始化加密保险库失败: %v", err)
	}

	authMgr, err := auth.NewManager(sessionTTL, false)
	if err != nil {
		log.Fatalf("[ServerNeedSafe] 初始化认证模块失败: %v", err)
	}

	sshMgr := sshmanager.NewManager(store)

	staticFS, err := web.DistFS()
	if err != nil {
		log.Fatalf("[ServerNeedSafe] 加载内置 Web 静态资源失败: %v", err)
	}

	apiServer := api.NewServer(api.Config{
		DeployMode: "server",
		Store:      store,
		Auth:       authMgr,
		SSH:        sshMgr,
		StaticFS:   staticFS,
	})

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		fmt.Printf("============================================================\n")
		fmt.Printf("  ServerNeedSafe — 多服务器安全管理与加密终端 (Web 服务端)\n")
		fmt.Printf("  监听地址: http://%s\n", *addr)
		fmt.Printf("  加密数据: %s\n", vaultPath)
		fmt.Printf("  安全算法: Argon2id + AES-256-GCM + XChaCha20-Poly1305\n")
		fmt.Printf("============================================================\n")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[ServerNeedSafe] HTTP 服务异常退出: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("[ServerNeedSafe] 收到停止信号，正在锁定保险库并安全清理内存密钥...")
	store.Lock("服务进程关闭自动锁定保险库", "system")
	apiServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}
