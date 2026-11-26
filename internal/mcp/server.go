package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/aiops"
	"github.com/icaruszezen/ServerNeedSafe/internal/monitor"
	"github.com/icaruszezen/ServerNeedSafe/internal/sshmanager"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

const (
	ServerName             = "serverneedsafe"
	ServerVersion          = "2.3.0"
	DefaultProtocolVersion = "2025-03-26"
	maxMCPBodyBytes        = 4 * 1024 * 1024
	sessionIdleTTL         = 12 * time.Hour
	maxActiveSessions      = 256
)

// Server implements a pure-Go Model Context Protocol (MCP) Streamable HTTP (JSON-RPC 2.0)
// gateway so Claude Code, Codex, Antigravity, Cursor, and other MCP clients can safely
// take over ServerNeedSafe AI patrol, read-only SSH/SFTP forensics, memory evolution,
// and HITL-gated remediation proposals without ever accessing raw SSH credentials.
type Server struct {
	store   *vault.Store
	ssh     *sshmanager.Manager
	monitor *monitor.Engine
	ai      *aiops.Service

	mu       sync.Mutex
	sessions map[string]*mcpSession
}

type mcpSession struct {
	ID         string
	TokenID    string
	ClientName string
	ClientVer  string
	Protocol   string
	CreatedAt  time.Time
	LastSeenAt time.Time
}

// NewServer constructs an MCP Streamable HTTP server backed by ServerNeedSafe core services.
func NewServer(store *vault.Store, sshMgr *sshmanager.Manager, mon *monitor.Engine, aiSvc *aiops.Service) *Server {
	return &Server{
		store:    store,
		ssh:      sshMgr,
		monitor:  mon,
		ai:       aiSvc,
		sessions: make(map[string]*mcpSession),
	}
}

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id"`
	Result  any           `json:"result,omitempty"`
	Error   *jsonRPCError `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// HTTPHandler returns an http.Handler serving /api/mcp over Streamable HTTP.
// When desktopLoopbackMode is true, it checks MCPConfig.DesktopLoopbackEnabled instead of MCPConfig.Enabled.
func (s *Server) HTTPHandler(desktopLoopbackMode bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.serveHTTP(w, r, desktopLoopbackMode)
	})
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request, desktopLoopbackMode bool) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version, X-MCP-Client")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id")
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if s.store == nil || !s.store.IsReady() {
		writeHTTPError(w, http.StatusServiceUnavailable, "VAULT_NOT_READY", "ServerNeedSafe 尚未初始化或保险库未就绪")
		return
	}

	// Strictly authenticate via persistent scoped MCP Bearer Token (NEVER accepts Web admin cookies/sessions)
	rawToken := extractBearerToken(r)
	if rawToken == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ServerNeedSafe MCP"`)
		writeHTTPError(w, http.StatusUnauthorized, "MCP_UNAUTHORIZED", "缺少有效的 MCP Bearer Token（请在 Header 中携带 Authorization: Bearer sns_mcp_...）")
		return
	}

	tok, enabled, err := s.store.AuthenticateMCPToken(rawToken)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ServerNeedSafe MCP", error="invalid_token"`)
		writeHTTPError(w, http.StatusUnauthorized, "MCP_INVALID_TOKEN", "MCP Token 无效或已被禁用/吊销")
		return
	}

	if desktopLoopbackMode {
		cfg, cfgErr := s.store.GetMCPConfigSecret()
		if cfgErr != nil || cfg == nil || !cfg.DesktopLoopbackEnabled {
			writeHTTPError(w, http.StatusForbidden, "MCP_DISABLED", "桌面版回环 MCP 接入未开启")
			return
		}
	} else if !enabled {
		writeHTTPError(w, http.StatusForbidden, "MCP_DISABLED", "外部 AI MCP 网关当前已关闭，请在 ServerNeedSafe「AI 智能运维 → 外部 AI 接管 (MCP)」中启用")
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Per MCP Streamable HTTP spec, servers that do not expose server-initiated SSE streams return 405.
		w.Header().Set("Allow", "POST, DELETE, OPTIONS")
		writeHTTPError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "本 MCP 端点使用 Streamable HTTP POST 模式，请通过 POST /api/mcp 发送 JSON-RPC 2.0 请求")
		return

	case http.MethodDelete:
		if sid := strings.TrimSpace(r.Header.Get("Mcp-Session-Id")); sid != "" {
			s.deleteSession(sid)
		}
		w.WriteHeader(http.StatusNoContent)
		return

	case http.MethodPost:
		// Handled below
	default:
		w.Header().Set("Allow", "POST, DELETE, OPTIONS")
		writeHTTPError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "仅支持 POST / DELETE / OPTIONS")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxMCPBodyBytes+1))
	if err != nil {
		writeHTTPError(w, http.StatusBadRequest, "BAD_BODY", "读取请求体失败")
		return
	}
	if len(body) > maxMCPBodyBytes {
		writeHTTPError(w, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "MCP 请求体超出大小限制")
		return
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		writeHTTPError(w, http.StatusBadRequest, "EMPTY_BODY", "请求体不能为空")
		return
	}

	clientIP := extractClientIP(r)
	sessionID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id"))
	headerClient := strings.TrimSpace(r.Header.Get("X-MCP-Client"))

	callCtx := &mcpCallContext{
		reqCtx:       r.Context(),
		token:        tok,
		clientIP:     clientIP,
		sessionID:    sessionID,
		headerClient: headerClient,
		userAgent:    strings.TrimSpace(r.UserAgent()),
	}

	// Support both single JSON-RPC request and JSON-RPC batch array
	if strings.HasPrefix(trimmed, "[") {
		var batch []jsonRPCRequest
		if err := json.Unmarshal([]byte(trimmed), &batch); err != nil || len(batch) == 0 {
			writeJSONRPC(w, http.StatusBadRequest, jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error:   &jsonRPCError{Code: -32700, Message: "Parse error: invalid JSON-RPC batch"},
			})
			return
		}
		responses := make([]jsonRPCResponse, 0, len(batch))
		for _, req := range batch {
			resp, newSID := s.handleRPC(callCtx, req)
			if newSID != "" {
				w.Header().Set("Mcp-Session-Id", newSID)
				callCtx.sessionID = newSID
			}
			if resp != nil {
				responses = append(responses, *resp)
			}
		}
		if len(responses) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(responses)
		return
	}

	var req jsonRPCRequest
	if err := json.Unmarshal([]byte(trimmed), &req); err != nil {
		writeJSONRPC(w, http.StatusBadRequest, jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      nil,
			Error:   &jsonRPCError{Code: -32700, Message: "Parse error: invalid JSON-RPC payload"},
		})
		return
	}

	resp, newSID := s.handleRPC(callCtx, req)
	if newSID != "" {
		w.Header().Set("Mcp-Session-Id", newSID)
	}
	if resp == nil {
		// Pure JSON-RPC notification -> 202 Accepted
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeJSONRPC(w, http.StatusOK, *resp)
}

type mcpCallContext struct {
	reqCtx       context.Context
	token        *vault.MCPToken
	clientIP     string
	sessionID    string
	headerClient string
	userAgent    string
}

func (s *Server) resolveClientName(c *mcpCallContext) string {
	if c.sessionID != "" {
		if sess := s.getSession(c.sessionID); sess != nil && sess.ClientName != "" {
			return friendlyClientName(sess.ClientName)
		}
	}
	if c.headerClient != "" {
		return friendlyClientName(c.headerClient)
	}
	if c.token != nil && c.token.ClientHint != "" && c.token.ClientHint != "custom" {
		return friendlyClientName(c.token.ClientHint)
	}
	if c.userAgent != "" {
		low := strings.ToLower(c.userAgent)
		switch {
		case strings.Contains(low, "claude"):
			return "Claude Code"
		case strings.Contains(low, "codex"):
			return "Codex"
		case strings.Contains(low, "antigravity"):
			return "Antigravity"
		case strings.Contains(low, "cursor"):
			return "Cursor"
		}
	}
	if c.token != nil && c.token.Name != "" {
		return c.token.Name
	}
	return "External MCP AI"
}

func friendlyClientName(raw string) string {
	t := strings.TrimSpace(raw)
	low := strings.ToLower(t)
	switch {
	case low == "claude_code" || low == "claude-code" || strings.Contains(low, "claude"):
		return "Claude Code"
	case low == "codex" || strings.Contains(low, "codex"):
		return "Codex"
	case low == "antigravity" || strings.Contains(low, "antigravity"):
		return "Antigravity"
	case low == "cursor" || strings.Contains(low, "cursor"):
		return "Cursor"
	default:
		return t
	}
}

func (s *Server) handleRPC(c *mcpCallContext, req jsonRPCRequest) (*jsonRPCResponse, string) {
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"
	var parsedID any
	if !isNotification {
		_ = json.Unmarshal(req.ID, &parsedID)
	}

	if req.JSONRPC != "" && req.JSONRPC != "2.0" {
		if isNotification {
			return nil, ""
		}
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      parsedID,
			Error:   &jsonRPCError{Code: -32600, Message: "Invalid Request: jsonrpc must be 2.0"},
		}, ""
	}

	// Handle notifications cleanly with no JSON-RPC response body
	if isNotification || strings.HasPrefix(req.Method, "notifications/") {
		if req.Method == "notifications/initialized" && c.sessionID != "" {
			s.touchSession(c.sessionID)
		}
		return nil, ""
	}

	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
			ClientInfo      struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"clientInfo"`
		}
		_ = json.Unmarshal(req.Params, &params)

		proto := DefaultProtocolVersion
		if p := strings.TrimSpace(params.ProtocolVersion); p == "2024-11-05" || p == "2025-03-26" || p == "2025-06-18" {
			proto = p
		}
		clientName := strings.TrimSpace(params.ClientInfo.Name)
		if clientName == "" {
			clientName = s.resolveClientName(c)
		}
		sid := s.createSession(c.token.ID, clientName, strings.TrimSpace(params.ClientInfo.Version), proto)
		s.store.RecordMCPTokenUsage(c.token.ID, friendlyClientName(clientName), c.clientIP)
		s.store.RecordAudit("mcp.connect", friendlyClientName(clientName), fmt.Sprintf("外部 AI 客户端建立 MCP 会话 (令牌=%s, 协议=%s)", c.token.Name, proto), c.clientIP, true)

		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      parsedID,
			Result: map[string]any{
				"protocolVersion": proto,
				"capabilities": map[string]any{
					"tools":     map[string]any{"listChanged": false},
					"resources": map[string]any{"subscribe": false, "listChanged": false},
					"prompts":   map[string]any{"listChanged": false},
				},
				"serverInfo": map[string]any{
					"name":    ServerName,
					"version": ServerVersion,
				},
				"instructions": "ServerNeedSafe 安全运维与 AI 巡检 MCP 网关。受管主机 SSH 密码/私钥已严格物理隔离。巡检时请优先调用 get_ops_context 或读取 serverneedsafe://agents-md 了解运维规范与主机画像；使用 list_patrol_records(pending_only=true) / claim_patrol 或 run_patrol 接管巡检，通过 exec_readonly_ssh / sftp_read_file 深度取证后调用 submit_patrol_report 回写结构化结论；如需线上修复变更，请调用 propose_ssh_command 或 propose_sftp_write 提交至 Web 端 HITL 审批队列。",
			},
		}, sid

	case "ping":
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      parsedID,
			Result:  map[string]any{},
		}, ""

	case "tools/list":
		s.touchSession(c.sessionID)
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      parsedID,
			Result: map[string]any{
				"tools": s.listToolsForToken(c.token),
			},
		}, ""

	case "tools/call":
		s.touchSession(c.sessionID)
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil || strings.TrimSpace(params.Name) == "" {
			return &jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      parsedID,
				Error:   &jsonRPCError{Code: -32602, Message: "Invalid params: missing tool name"},
			}, ""
		}
		clientName := s.resolveClientName(c)
		s.store.RecordMCPTokenUsage(c.token.ID, clientName, c.clientIP)
		resultText, isErr := s.callTool(c, clientName, strings.TrimSpace(params.Name), params.Arguments)
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      parsedID,
			Result: map[string]any{
				"content": []map[string]any{
					{
						"type": "text",
						"text": resultText,
					},
				},
				"isError": isErr,
			},
		}, ""

	case "resources/list":
		s.touchSession(c.sessionID)
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      parsedID,
			Result: map[string]any{
				"resources": s.listResources(),
			},
		}, ""

	case "resources/read":
		s.touchSession(c.sessionID)
		var params struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil || strings.TrimSpace(params.URI) == "" {
			return &jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      parsedID,
				Error:   &jsonRPCError{Code: -32602, Message: "Invalid params: missing resource uri"},
			}, ""
		}
		s.store.RecordMCPTokenUsage(c.token.ID, s.resolveClientName(c), c.clientIP)
		mime, text, err := s.readResource(c.token, strings.TrimSpace(params.URI))
		if err != nil {
			return &jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      parsedID,
				Error:   &jsonRPCError{Code: -32002, Message: err.Error()},
			}, ""
		}
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      parsedID,
			Result: map[string]any{
				"contents": []map[string]any{
					{
						"uri":      params.URI,
						"mimeType": mime,
						"text":     text,
					},
				},
			},
		}, ""

	case "prompts/list":
		s.touchSession(c.sessionID)
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      parsedID,
			Result: map[string]any{
				"prompts": s.listPrompts(),
			},
		}, ""

	case "prompts/get":
		s.touchSession(c.sessionID)
		var params struct {
			Name      string            `json:"name"`
			Arguments map[string]string `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil || strings.TrimSpace(params.Name) == "" {
			return &jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      parsedID,
				Error:   &jsonRPCError{Code: -32602, Message: "Invalid params: missing prompt name"},
			}, ""
		}
		desc, messages, err := s.getPrompt(strings.TrimSpace(params.Name), params.Arguments)
		if err != nil {
			return &jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      parsedID,
				Error:   &jsonRPCError{Code: -32602, Message: err.Error()},
			}, ""
		}
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      parsedID,
			Result: map[string]any{
				"description": desc,
				"messages":    messages,
			},
		}, ""

	default:
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      parsedID,
			Error:   &jsonRPCError{Code: -32601, Message: fmt.Sprintf("Method not found: %s", req.Method)},
		}, ""
	}
}

func (s *Server) createSession(tokenID, clientName, clientVer, proto string) string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	sid := hex.EncodeToString(buf)
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()
	// Prune idle sessions
	for k, sess := range s.sessions {
		if now.Sub(sess.LastSeenAt) > sessionIdleTTL {
			delete(s.sessions, k)
		}
	}
	if len(s.sessions) >= maxActiveSessions {
		// Evict oldest session
		var oldestKey string
		var oldestTime time.Time
		for k, sess := range s.sessions {
			if oldestKey == "" || sess.LastSeenAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = sess.LastSeenAt
			}
		}
		if oldestKey != "" {
			delete(s.sessions, oldestKey)
		}
	}
	s.sessions[sid] = &mcpSession{
		ID:         sid,
		TokenID:    tokenID,
		ClientName: clientName,
		ClientVer:  clientVer,
		Protocol:   proto,
		CreatedAt:  now,
		LastSeenAt: now,
	}
	return sid
}

func (s *Server) getSession(sid string) *mcpSession {
	if sid == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sid]
	if !ok {
		return nil
	}
	cp := *sess
	return &cp
}

func (s *Server) touchSession(sid string) {
	if sid == "" {
		return
	}
	s.mu.Lock()
	if sess, ok := s.sessions[sid]; ok {
		sess.LastSeenAt = time.Now().UTC()
	}
	s.mu.Unlock()
}

func (s *Server) deleteSession(sid string) {
	s.mu.Lock()
	delete(s.sessions, sid)
	s.mu.Unlock()
}

func extractBearerToken(r *http.Request) string {
	hdr := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(hdr), "bearer ") {
		return strings.TrimSpace(hdr[7:])
	}
	return ""
}

func extractClientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 && strings.TrimSpace(parts[0]) != "" {
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func writeJSONRPC(w http.ResponseWriter, status int, payload jsonRPCResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeHTTPError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": message,
		"code":  code,
	})
}
