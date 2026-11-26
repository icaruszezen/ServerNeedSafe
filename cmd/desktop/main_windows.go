//go:build windows

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/icaruszezen/ServerNeedSafe/internal/api"
	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/updater"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/icaruszezen/ServerNeedSafe/internal/version"
	"github.com/icaruszezen/ServerNeedSafe/web"
	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

const (
	windowTitle     = "ServerNeedSafe — 多服务器安全运维与 7×24 智能巡检工作台"
	singleMutexName = "Local\\ServerNeedSafe_Desktop_Singleton_v1"
)

var (
	user32                        = windows.NewLazySystemDLL("user32.dll")
	procSetProcessDpiAwarenessCtx = user32.NewProc("SetProcessDpiAwarenessContext")
	procFindWindowW               = user32.NewProc("FindWindowW")
	procShowWindow                = user32.NewProc("ShowWindow")
	procSetForegroundWindow       = user32.NewProc("SetForegroundWindow")
	procMessageBoxW               = user32.NewProc("MessageBoxW")
)

func enableHighDPI() {
	// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
	if err := procSetProcessDpiAwarenessCtx.Find(); err == nil {
		_, _, _ = procSetProcessDpiAwarenessCtx.Call(^uintptr(3))
	}
}

func showMessageBox(title, text string, flags uintptr) int {
	tPtr, _ := syscall.UTF16PtrFromString(title)
	mPtr, _ := syscall.UTF16PtrFromString(text)
	ret, _, _ := procMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(mPtr)),
		uintptr(unsafe.Pointer(tPtr)),
		flags,
	)
	return int(ret)
}

func focusExistingWindow() {
	if tPtr, err := syscall.UTF16PtrFromString(windowTitle); err == nil {
		hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(tPtr)))
		if hwnd != 0 {
			// SW_RESTORE = 9
			_, _, _ = procShowWindow.Call(hwnd, 9)
			_, _, _ = procSetForegroundWindow.Call(hwnd)
		}
	}
}

// resolveLocalDataDir prefers portable ./data next to the .exe if writable;
// otherwise falls back to %LOCALAPPDATA%\ServerNeedSafe\data.
func resolveLocalDataDir() (dataDir string, webviewDir string, err error) {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		home, _ := os.UserHomeDir()
		localAppData = filepath.Join(home, "AppData", "Local")
	}
	webviewDir = filepath.Join(localAppData, "ServerNeedSafe", "webview2-runtime")
	_ = os.MkdirAll(webviewDir, 0o700)

	if envDir := os.Getenv("SNS_DATA_DIR"); envDir != "" {
		if err := os.MkdirAll(envDir, 0o700); err == nil {
			return envDir, webviewDir, nil
		}
	}

	if exePath, err := os.Executable(); err == nil {
		portableDir := filepath.Join(filepath.Dir(exePath), "data")
		if mkErr := os.MkdirAll(portableDir, 0o700); mkErr == nil {
			probeFile := filepath.Join(portableDir, ".write_test")
			if f, wErr := os.OpenFile(probeFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); wErr == nil {
				_ = f.Close()
				_ = os.Remove(probeFile)
				return portableDir, webviewDir, nil
			}
		}
	}

	fallback := filepath.Join(localAppData, "ServerNeedSafe", "data")
	if err := os.MkdirAll(fallback, 0o700); err != nil {
		return "", "", err
	}
	return fallback, webviewDir, nil
}

func main() {
	// Support `--version` before acquiring singleton mutex or initializing WebView2 (used by pre-swap self-check).
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-version" || arg == "-v" {
			fmt.Println(version.String())
			return
		}
	}

	enableHighDPI()

	// Ensure single running local desktop instance
	mutexPtr, _ := syscall.UTF16PtrFromString(singleMutexName)
	mutexHandle, err := windows.CreateMutex(nil, false, mutexPtr)
	if err == windows.ERROR_ALREADY_EXISTS {
		focusExistingWindow()
		return
	}
	if mutexHandle != 0 {
		defer func() {
			if mutexHandle != 0 {
				_ = windows.CloseHandle(mutexHandle)
				mutexHandle = 0
			}
		}()
	}

	updater.CleanupPreviousBackup()

	dataDir, webviewDir, err := resolveLocalDataDir()
	if err != nil {
		showMessageBox("ServerNeedSafe 启动失败", fmt.Sprintf("无法创建本地数据目录:\n%v", err), 0x10)
		return
	}

	store, err := vault.NewStore(dataDir)
	if err != nil {
		showMessageBox("ServerNeedSafe 启动失败", fmt.Sprintf("初始化本地加密存储失败:\n%v", err), 0x10)
		return
	}
	vaultPath := store.SecretsPath()

	// Enable desktop loopback instance guard so external local web pages cannot call /api/*
	authMgr, err := auth.NewManager(auth.DefaultSessionTTL, true)
	if err != nil {
		showMessageBox("ServerNeedSafe 启动失败", fmt.Sprintf("初始化安全认证引擎失败:\n%v", err), 0x10)
		return
	}

	staticFS, err := web.DistFS()
	if err != nil {
		showMessageBox("ServerNeedSafe 启动失败", fmt.Sprintf("加载内置前端静态资源失败:\n%v", err), 0x10)
		return
	}

	// Bind strictly to 127.0.0.1:0 (pure-local loopback, unreachable from LAN)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		showMessageBox("ServerNeedSafe 启动失败", fmt.Sprintf("绑定本地回环引擎失败:\n%v", err), 0x10)
		return
	}

	var (
		wvMu      sync.Mutex
		wvInst    webview2.WebView
		httpSrv   *http.Server
		apiSrv    *api.Server
		closeOnce sync.Once
	)
	shutdownAll := func() {
		closeOnce.Do(func() {
			authMgr.RevokeAll()
			if apiSrv != nil {
				apiSrv.Close()
			}
			if httpSrv != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_ = httpSrv.Shutdown(ctx)
			}
			if mutexHandle != 0 {
				_ = windows.CloseHandle(mutexHandle)
				mutexHandle = 0
			}
		})
	}

	apiSrv = api.NewServer(api.Config{
		DeployMode: "desktop",
		Store:      store,
		Auth:       authMgr,
		StaticFS:   staticFS,
		OnRestart: func(exePath, backupPath string) error {
			// On Windows, StageAndReplaceBinary has already launched the detached swap helper
			// waiting on our PID. Terminate the WebView2 loop (or exit directly in fallback mode)
			// so stores flush and the singleton mutex releases cleanly.
			wvMu.Lock()
			w := wvInst
			wvMu.Unlock()
			if w != nil {
				w.Dispatch(func() {
					w.Terminate()
				})
				return nil
			}
			go func() {
				shutdownAll()
				os.Exit(0)
			}()
			return nil
		},
	})

	httpSrv = &http.Server{
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		_ = httpSrv.Serve(ln)
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	bootURL := fmt.Sprintf("http://127.0.0.1:%d/__desktop_boot?boot=%s", port, authMgr.DesktopBootCode())

	// Launch native Windows WebView2 GUI window
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     os.Getenv("SNS_DEBUG") == "1",
		AutoFocus: true,
		DataPath:  webviewDir,
		WindowOptions: webview2.WindowOptions{
			Title:  windowTitle,
			Width:  1380,
			Height: 880,
			IconId: 0,
			Center: true,
		},
	})

	if w != nil {
		wvMu.Lock()
		wvInst = w
		wvMu.Unlock()

		w.Navigate(bootURL)
		w.Run()

		wvMu.Lock()
		wvInst = nil
		wvMu.Unlock()
		w.Destroy()
	} else {
		// Fallback for older Windows Server environments lacking Edge WebView2 runtime
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", bootURL).Start()
		showMessageBox(
			windowTitle,
			fmt.Sprintf(
				"未检测到 Microsoft Edge WebView2 运行时，已在系统默认浏览器中打开纯本地安全管理控制台。\n\n加密保险库路径：\n%s\n\n点击【确定】将立即注销会话并退出 ServerNeedSafe 本地进程。",
				vaultPath,
			),
			0x40,
		)
	}

	// Revoke sessions, flush runtime stores, close loopback engine, and release singleton mutex
	shutdownAll()
}
