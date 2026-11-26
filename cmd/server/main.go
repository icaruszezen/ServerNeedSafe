package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/api"
	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
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
	defaultTTL := envOrDefault("SNS_SESSION_TTL", "168h")

	addr := flag.String("addr", defaultAddr, "HTTP 监听地址 (例如 0.0.0.0:8080)")
	dataDir := flag.String("data-dir", defaultDataDir, "数据持久化目录（secrets.enc + master.key + 运行态 JSON）")
	ttlStr := flag.String("session-ttl", defaultTTL, "Web 管理会话最长有效期（默认 168h / 7 天）")
	flag.Parse()

	sessionTTL, err := time.ParseDuration(*ttlStr)
	if err != nil || sessionTTL <= 0 {
		sessionTTL = auth.DefaultSessionTTL
	}

	store, err := vault.NewStore(*dataDir)
	if err != nil {
		log.Fatalf("[ServerNeedSafe] 初始化分层加密存储失败: %v", err)
	}

	authMgr, err := auth.NewManager(sessionTTL, false)
	if err != nil {
		log.Fatalf("[ServerNeedSafe] 初始化认证会话引擎失败: %v", err)
	}

	staticFS, err := web.DistFS()
	if err != nil {
		log.Fatalf("[ServerNeedSafe] 加载内置 Web 静态资源失败: %v", err)
	}

	apiServer := api.NewServer(api.Config{
		DeployMode: "server",
		Store:      store,
		Auth:       authMgr,
		StaticFS:   staticFS,
	})

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	keyDesc := store.MasterKeyPath() + " (0600 本地密钥)"
	if store.MasterKeyMode() == vault.MasterKeyModeEnv {
		keyDesc = "SNS_MASTER_KEY 环境变量注入"
	}

	go func() {
		fmt.Printf("====================================================================\n")
		fmt.Printf("  ServerNeedSafe — 多服务器运维管理与 7×24 智能监控巡检平台\n")
		fmt.Printf("  监听地址: http://%s\n", *addr)
		fmt.Printf("  敏感加密: %s (XChaCha20-Poly1305)\n", store.SecretsPath())
		fmt.Printf("  主密钥源: %s（启动即自动挂载，永不锁定后台任务）\n", keyDesc)
		fmt.Printf("  运行存储: %s/{monitor,aiops,audit}_runtime.json（独立防抖落盘）\n", store.DataDir())
		fmt.Printf("  会话周期: %s（建议部署于内网或安全受控主机）\n", sessionTTL)
		fmt.Printf("====================================================================\n")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[ServerNeedSafe] HTTP 服务异常退出: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("[ServerNeedSafe] 收到停止信号，正在同步刷盘运行态数据并停止 7×24 守护协程...")
	authMgr.RevokeAll()
	apiServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}
