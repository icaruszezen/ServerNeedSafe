package api

import (
	"net"
	"net/http"
	"strings"
)

// sessionGoneTerminalMsg is sent to an interactive SSH terminal before it is closed because the admin
// session that opened it was revoked or expired.
const sessionGoneTerminalMsg = "管理会话已失效（已锁定、注销或超时），SSH 终端已安全断开，请重新登录"

// extractClientIP extracts the best-effort caller IP for audit logs, supporting common intranet and
// public reverse proxies (X-Real-IP / X-Forwarded-For) with fallback to RemoteAddr.
func extractClientIP(r *http.Request) string {
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" && net.ParseIP(realIP) != nil {
		return realIP
	}
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		for _, part := range strings.Split(xff, ",") {
			if ip := strings.TrimSpace(part); ip != "" && net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return r.RemoteAddr
	}
	return host
}
