package qqbot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

const (
	defaultMinHeartbeatInterval = 5 * time.Second
	defaultMaxHeartbeatInterval = 5 * time.Minute
	defaultBaseReconnectBackoff = 2 * time.Second
	defaultMaxReconnectBackoff  = 60 * time.Second
)

type sessionOutcome struct {
	action CloseAction
	err    error
}

// supervisorLoop keeps the QQ Open Platform WebSocket Gateway connection healthy 7x24 whenever enabled.
func (s *Service) supervisorLoop() {
	defer close(s.doneCh)

	backoff := s.effectiveBaseBackoff()

	for {
		select {
		case <-s.stopCh:
			s.setStoppedState("disabled", "")
			return
		default:
		}

		if s.store == nil || !s.store.IsReady() {
			s.setStoppedState("disabled", "")
			if !s.waitForWakeOrTimeout(3 * time.Second) {
				return
			}
			continue
		}

		cfg, err := s.store.GetQQBotSettings()
		if err != nil || !cfg.Enabled || strings.TrimSpace(cfg.AppID) == "" || strings.TrimSpace(cfg.AppSecret) == "" {
			s.resetSessionResumeState()
			s.setStoppedState("disabled", "")
			if !s.waitForWakeOrTimeout(30 * time.Second) {
				return
			}
			continue
		}

		// If configuration identity changed (AppID, Sandbox, Intents, Shard, APIBaseURL), discard stale session_id.
		sig := configFingerprint(cfg)
		s.mu.Lock()
		if s.lastConfigSig != "" && s.lastConfigSig != sig {
			s.sessionID = ""
			s.lastSeq = 0
			s.canResume = false
			s.pausedError = false
		}
		s.lastConfigSig = sig
		paused := s.pausedError
		s.mu.Unlock()

		if paused {
			if !s.waitForWakeOrTimeout(60 * time.Second) {
				return
			}
			continue
		}

		// Create a per-session context canceled on Close(), NotifyConfigUpdated(), or ReconnectNow().
		sessCtx, sessCancel := context.WithCancel(context.Background())
		s.mu.Lock()
		s.sessionCancel = sessCancel
		s.mu.Unlock()

		outcome := s.runSingleSession(sessCtx, cfg)

		s.mu.Lock()
		s.sessionCancel = nil
		connected := s.connected
		s.connected = false
		s.mu.Unlock()
		sessCancel()

		// Exit immediately if service is closing.
		select {
		case <-s.stopCh:
			s.setStoppedState("disabled", "")
			return
		default:
		}

		// If session was canceled because config changed or manual reconnect was requested, loop immediately.
		if errors.Is(outcome.err, context.Canceled) {
			backoff = s.effectiveBaseBackoff()
			continue
		}

		if connected {
			// Connection was healthy before dropping — reset backoff so recovery is swift.
			backoff = s.effectiveBaseBackoff()
		}

		switch outcome.action {
		case CloseActionFatalBanned:
			msg := outcome.err.Error()
			s.mu.Lock()
			s.state = "stopped_error"
			s.lastError = msg
			s.sessionID = ""
			s.lastSeq = 0
			s.canResume = false
			s.pausedError = true
			s.mu.Unlock()
			s.store.RecordAuditAsync("qqbot.ws_fatal", "qqbot-gateway", msg, "qqbot-gateway", false)
			if !s.waitForWakeOrTimeout(5 * time.Minute) {
				return
			}

		case CloseActionConfigError:
			msg := outcome.err.Error()
			s.mu.Lock()
			s.state = "error"
			s.lastError = msg
			s.sessionID = ""
			s.lastSeq = 0
			s.canResume = false
			s.pausedError = true
			s.mu.Unlock()
			s.store.RecordAuditAsync("qqbot.ws_config_error", "qqbot-gateway", msg, "qqbot-gateway", false)
			if !s.waitForWakeOrTimeout(5 * time.Minute) {
				return
			}

		case CloseActionResume:
			s.mu.Lock()
			s.state = "reconnecting"
			s.reconnectCount++
			if outcome.err != nil {
				s.lastError = outcome.err.Error()
			}
			s.canResume = s.sessionID != ""
			s.mu.Unlock()
			if !s.waitForWakeOrTimeout(backoff) {
				return
			}
			backoff = min(backoff*2, s.effectiveMaxBackoff())

		default: // CloseActionReidentify
			s.mu.Lock()
			s.state = "reconnecting"
			s.reconnectCount++
			if outcome.err != nil {
				s.lastError = outcome.err.Error()
			}
			s.sessionID = ""
			s.lastSeq = 0
			s.canResume = false
			s.mu.Unlock()
			if !s.waitForWakeOrTimeout(backoff) {
				return
			}
			backoff = min(backoff*2, s.effectiveMaxBackoff())
		}
	}
}

func (s *Service) runSingleSession(ctx context.Context, cfg vault.QQBotSettings) sessionOutcome {
	s.mu.Lock()
	s.state = "connecting"
	s.mu.Unlock()

	// Step 1 & 2: Acquire AccessToken and query GET /gateway/bot (or /gateway)
	gwCtx, gwCancel := context.WithTimeout(ctx, 18*time.Second)
	gwInfo, token, err := s.client.GetGatewayInfo(gwCtx, cfg)
	gwCancel()
	if err != nil {
		if ctx.Err() != nil {
			return sessionOutcome{action: CloseActionReidentify, err: context.Canceled}
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) && (apiErr.ErrCode == 100007 || apiErr.ErrCode == 100016 || apiErr.ErrCode == 10004) {
			return sessionOutcome{action: CloseActionConfigError, err: err}
		}
		return sessionOutcome{action: CloseActionReidentify, err: err}
	}

	s.mu.Lock()
	s.gatewayURL = gwInfo.URL
	if gwInfo.Shards > 0 {
		s.recommendedShards = gwInfo.Shards
	}
	if gwInfo.SessionStartLimit != nil {
		s.sessionTotal = gwInfo.SessionStartLimit.Total
		s.sessionRemaining = gwInfo.SessionStartLimit.Remaining
	}
	s.mu.Unlock()

	// Step 3: Dial WebSocket Gateway URL
	dialer := s.wsDialer
	if dialer == nil {
		dialer = &websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 15 * time.Second,
		}
	}
	conn, _, err := dialer.DialContext(ctx, gwInfo.URL, http.Header{
		"User-Agent": []string{"ServerNeedSafe-QQBot/2.0"},
	})
	if err != nil {
		if ctx.Err() != nil {
			return sessionOutcome{action: CloseActionReidentify, err: context.Canceled}
		}
		return sessionOutcome{action: CloseActionReidentify, err: fmt.Errorf("连接 QQ WebSocket 网关失败: %w", err)}
	}
	defer conn.Close()

	// Close socket promptly when session context is canceled
	connDone := make(chan struct{})
	defer close(connDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "shutdown"), time.Now().Add(2*time.Second))
			_ = conn.Close()
		case <-connDone:
		}
	}()

	var writeMu sync.Mutex
	writeJSON := func(v any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return conn.WriteJSON(v)
	}

	// Step 4: Expect OpCode 10 Hello as the very first gateway frame
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	var helloPayload GatewayPayload
	if err := conn.ReadJSON(&helloPayload); err != nil {
		return s.classifyReadErr(ctx, err, "等待网关 OpCode 10 Hello 失败")
	}
	if helloPayload.Op != OpHello {
		return sessionOutcome{
			action: CloseActionReidentify,
			err:    fmt.Errorf("预期网关发送 OpCode 10 Hello，实际收到 op=%d", helloPayload.Op),
		}
	}
	var hello HelloData
	if err := json.Unmarshal(helloPayload.D, &hello); err != nil || hello.HeartbeatInterval <= 0 {
		hello.HeartbeatInterval = 45000
	}
	hbInterval := time.Duration(hello.HeartbeatInterval) * time.Millisecond
	minHB := s.effectiveMinHeartbeat()
	if hbInterval < minHB {
		hbInterval = minHB
	}
	if hbInterval > defaultMaxHeartbeatInterval {
		hbInterval = defaultMaxHeartbeatInterval
	}

	s.mu.Lock()
	s.heartbeatIntervalMs = hello.HeartbeatInterval
	resumeSID := s.sessionID
	resumeSeq := s.lastSeq
	shouldResume := s.canResume && resumeSID != "" && resumeSeq > 0
	s.mu.Unlock()

	// Step 5: Send OpCode 6 Resume (if recovering an active session) or OpCode 2 Identify
	if shouldResume {
		s.mu.Lock()
		s.state = "resuming"
		s.mu.Unlock()
		resumeMsg := map[string]any{
			"op": OpResume,
			"d": ResumeData{
				Token:     "QQBot " + token,
				SessionID: resumeSID,
				Seq:       resumeSeq,
			},
		}
		if err := writeJSON(resumeMsg); err != nil {
			return sessionOutcome{action: CloseActionResume, err: fmt.Errorf("发送 OpCode 6 Resume 失败: %w", err)}
		}
	} else {
		s.mu.Lock()
		s.state = "identifying"
		s.mu.Unlock()
		shard := [2]int{cfg.ShardID, cfg.ShardCount}
		identifyMsg := map[string]any{
			"op": OpIdentify,
			"d": IdentifyData{
				Token:   "QQBot " + token,
				Intents: cfg.Intents,
				Shard:   shard,
				Properties: map[string]string{
					"$os":      runtime.GOOS,
					"$browser": "ServerNeedSafe",
					"$device":  "ServerNeedSafe",
				},
			},
		}
		if err := writeJSON(identifyMsg); err != nil {
			return sessionOutcome{action: CloseActionReidentify, err: fmt.Errorf("发送 OpCode 2 Identify 鉴权失败: %w", err)}
		}
	}

	// Step 6: Start periodic OpCode 1 Heartbeat goroutine with missed-ACK zombie detection
	hbStop := make(chan struct{})
	var hbWG sync.WaitGroup
	var hbMu sync.Mutex
	var lastHeartbeatSent time.Time
	var pendingACK bool
	var missedACKs int

	sendHeartbeat := func() error {
		s.mu.RLock()
		seq := s.lastSeq
		s.mu.RUnlock()

		var d any
		if seq > 0 {
			d = seq
		}
		hbMu.Lock()
		lastHeartbeatSent = time.Now()
		pendingACK = true
		hbMu.Unlock()
		return writeJSON(map[string]any{
			"op": OpHeartbeat,
			"d":  d,
		})
	}

	hbErrCh := make(chan error, 1)
	hbWG.Add(1)
	go func() {
		defer hbWG.Done()
		ticker := time.NewTicker(hbInterval)
		defer ticker.Stop()
		for {
			select {
			case <-hbStop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				hbMu.Lock()
				if pendingACK {
					missedACKs++
				}
				missed := missedACKs
				hbMu.Unlock()
				if missed >= 2 {
					select {
					case hbErrCh <- fmt.Errorf("连续 %d 次未收到 QQ 网关 OpCode 11 Heartbeat ACK，主动重建连接", missed):
					default:
					}
					_ = conn.Close()
					return
				}
				if err := sendHeartbeat(); err != nil {
					select {
					case hbErrCh <- fmt.Errorf("发送 OpCode 1 心跳失败: %w", err):
					default:
					}
					_ = conn.Close()
					return
				}
			}
		}
	}()
	defer func() {
		close(hbStop)
		hbWG.Wait()
	}()

	// Clear initial tight deadline; heartbeat loop + read deadline keeps socket bounded
	readTimeout := max(hbInterval*3, 30*time.Second)

	// Step 7: Main Gateway Read Loop
	for {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		var payload GatewayPayload
		if err := conn.ReadJSON(&payload); err != nil {
			select {
			case hbErr := <-hbErrCh:
				return sessionOutcome{action: CloseActionResume, err: hbErr}
			default:
			}
			return s.classifyReadErr(ctx, err, "读取 QQ WebSocket 网关消息失败")
		}

		if payload.S > 0 {
			s.mu.Lock()
			if payload.S > s.lastSeq {
				s.lastSeq = payload.S
			}
			s.mu.Unlock()
		}

		switch payload.Op {
		case OpHeartbeatACK:
			now := time.Now().UTC()
			hbMu.Lock()
			var rtt int64
			if !lastHeartbeatSent.IsZero() {
				rtt = max(1, time.Since(lastHeartbeatSent).Milliseconds())
			}
			pendingACK = false
			missedACKs = 0
			hbMu.Unlock()

			s.mu.Lock()
			s.lastHeartbeatAckAt = &now
			if rtt > 0 {
				s.heartbeatLatencyMs = rtt
			}
			s.mu.Unlock()

		case OpHeartbeat:
			// Server requested an immediate heartbeat
			if err := sendHeartbeat(); err != nil {
				return sessionOutcome{action: CloseActionResume, err: fmt.Errorf("回复服务端心跳请求失败: %w", err)}
			}

		case OpReconnect:
			s.recordControlEvent(payload, "RECONNECT", "QQ 网关下发 OpCode 7 Reconnect，正在无缝恢复会话")
			return sessionOutcome{action: CloseActionResume, err: fmt.Errorf("QQ 网关要求重新连接 (OpCode 7)")}

		case OpInvalidSession:
			var resumable bool
			_ = json.Unmarshal(payload.D, &resumable)
			s.recordControlEvent(payload, "INVALID_SESSION", fmt.Sprintf("QQ 网关返回 OpCode 9 Invalid Session (resumable=%v)", resumable))
			if resumable {
				return sessionOutcome{action: CloseActionResume, err: fmt.Errorf("网关返回 OpCode 9 Invalid Session，尝试 Resume")}
			}
			return sessionOutcome{action: CloseActionReidentify, err: fmt.Errorf("网关返回 OpCode 9 Invalid Session，将重新 Identify 鉴权")}

		case OpDispatch:
			switch payload.T {
			case "READY":
				var ready ReadyEvent
				if err := json.Unmarshal(payload.D, &ready); err == nil {
					now := time.Now().UTC()
					s.mu.Lock()
					s.sessionID = ready.SessionID
					s.botUserID = ready.User.ID
					s.botUsername = ready.User.Username
					s.connected = true
					s.state = "connected"
					s.connectedSince = &now
					s.lastError = ""
					s.canResume = true
					s.mu.Unlock()
					s.recordControlEvent(payload, "READY", fmt.Sprintf("鉴权成功，机器人 %s (%s) 已在线", ready.User.Username, ready.User.ID))
					// Send an immediate first heartbeat so ACK latency is measured right away
					_ = sendHeartbeat()
				}

			case "RESUMED":
				now := time.Now().UTC()
				s.mu.Lock()
				s.connected = true
				s.state = "connected"
				s.connectedSince = &now
				s.lastError = ""
				s.resumeCount++
				s.canResume = true
				s.mu.Unlock()
				s.recordControlEvent(payload, "RESUMED", "断线重连 Resume 成功，漏发事件已补发完成")

			default:
				s.mu.Lock()
				s.eventsReceived++
				s.mu.Unlock()
				s.handleDispatchAsync(ctx, cfg, payload)
			}
		}
	}
}

func (s *Service) classifyReadErr(ctx context.Context, err error, prefix string) sessionOutcome {
	if ctx.Err() != nil {
		return sessionOutcome{action: CloseActionReidentify, err: context.Canceled}
	}
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		action, diag := ClassifyCloseCode(ce.Code)
		if ce.Text != "" {
			diag = fmt.Sprintf("%s (%s)", diag, ce.Text)
		}
		return sessionOutcome{action: action, err: errors.New(diag)}
	}
	return sessionOutcome{action: CloseActionResume, err: fmt.Errorf("%s: %w", prefix, err)}
}

// ProbeConnection tests AccessToken acquisition, /gateway/bot lookup, and WebSocket OpCode 10 Hello handshake.
func (s *Service) ProbeConnection(ctx context.Context, cfg vault.QQBotSettings) (*ProbeResult, error) {
	start := time.Now()
	cfg = vault.NormalizeQQBotSettings(cfg)
	if cfg.AppID == "" || cfg.AppSecret == "" {
		return nil, fmt.Errorf("%w: 请先填写 AppID 与 AppSecret", vault.ErrInvalidInput)
	}

	probeClient := NewAPIClient(s.client.httpClient)
	gwInfo, _, err := probeClient.GetGatewayInfo(ctx, cfg)
	if err != nil {
		return nil, err
	}

	dialer := s.wsDialer
	if dialer == nil {
		dialer = &websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 12 * time.Second,
		}
	}
	conn, _, err := dialer.DialContext(ctx, gwInfo.URL, http.Header{
		"User-Agent": []string{"ServerNeedSafe-QQBot/2.0"},
	})
	if err != nil {
		return nil, fmt.Errorf("已获取 AccessToken 与网关地址 (%s)，但建立 WebSocket 握手失败: %w", gwInfo.URL, err)
	}
	defer func() {
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "probe"), time.Now().Add(1*time.Second))
		_ = conn.Close()
	}()

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var helloPayload GatewayPayload
	if err := conn.ReadJSON(&helloPayload); err != nil {
		return nil, fmt.Errorf("WebSocket 已连上但未收到 OpCode 10 Hello: %w", err)
	}
	if helloPayload.Op != OpHello {
		return nil, fmt.Errorf("WebSocket 握手首包异常：期望 OpCode 10 Hello，实际 op=%d", helloPayload.Op)
	}
	var hello HelloData
	_ = json.Unmarshal(helloPayload.D, &hello)

	res := &ProbeResult{
		OK:                  true,
		LatencyMs:           max(1, time.Since(start).Milliseconds()),
		GatewayURL:          gwInfo.URL,
		RecommendedShards:   gwInfo.Shards,
		HeartbeatIntervalMs: hello.HeartbeatInterval,
	}
	if gwInfo.SessionStartLimit != nil {
		res.SessionTotal = gwInfo.SessionStartLimit.Total
		res.SessionRemaining = gwInfo.SessionStartLimit.Remaining
	}
	return res, nil
}
