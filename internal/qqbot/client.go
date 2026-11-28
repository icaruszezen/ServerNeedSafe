package qqbot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

const (
	defaultTokenRefreshLead = 90 * time.Second
	maxQQMessageRunes       = 1800
)

// SendMessageRequest describes an outbound QQ Open Platform API v2 message delivery.
type SendMessageRequest struct {
	TargetType vault.QQBotTargetType
	TargetID   string
	Format     string // "text" or "markdown"
	PlainText  string
	Markdown   string
	MsgID      string // Optional passive reply message ID
	EventID    string // Optional passive reply event ID
	MsgSeq     int    // Sequence number paired with MsgID (>=1)
}

// SendMessageResponse captures the QQ OpenAPI message send result.
type SendMessageResponse struct {
	ID            string `json:"id"`
	Timestamp     string `json:"timestamp"`
	UsedFormat    string `json:"used_format"`
	AuditPending  bool   `json:"audit_pending,omitempty"`
	FallbackPlain bool   `json:"fallback_plain,omitempty"`
}

// APIError represents an error returned by QQ Open Platform HTTP OpenAPI.
type APIError struct {
	StatusCode int
	ErrCode    int
	Message    string
	TraceID    string
	RawBody    string
}

func (e *APIError) Error() string {
	if e.ErrCode != 0 {
		if e.TraceID != "" {
			return fmt.Sprintf("QQ 开放平台接口返回错误 (HTTP %d, code=%d, trace=%s): %s", e.StatusCode, e.ErrCode, e.TraceID, e.Message)
		}
		return fmt.Sprintf("QQ 开放平台接口返回错误 (HTTP %d, code=%d): %s", e.StatusCode, e.ErrCode, e.Message)
	}
	if e.Message != "" {
		return fmt.Sprintf("QQ 开放平台接口错误 (HTTP %d): %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("QQ 开放平台接口错误 (HTTP %d)", e.StatusCode)
}

func (e *APIError) isTokenError() bool {
	if e == nil {
		return false
	}
	if e.StatusCode == http.StatusUnauthorized {
		return true
	}
	switch e.ErrCode {
	case 11241, 11242, 11243:
		return true
	default:
		return false
	}
}

// APIClient handles QQ Open Platform v2 AccessToken lifecycle, Gateway lookup, and message delivery.
type APIClient struct {
	httpClient *http.Client
	nowFn      func() time.Time

	tokenMu     sync.Mutex
	cacheKey    string
	cachedToken string
	expiresAt   time.Time
}

// NewAPIClient constructs an APIClient with sensible production timeouts and proxy support.
func NewAPIClient(httpClient *http.Client) *APIClient {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 18 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				MaxIdleConns:          16,
				IdleConnTimeout:       60 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 15 * time.Second,
			},
		}
	}
	return &APIClient{
		httpClient: httpClient,
		nowFn:      time.Now,
	}
}

func (c *APIClient) now() time.Time {
	if c.nowFn != nil {
		return c.nowFn()
	}
	return time.Now()
}

// InvalidateToken clears the cached AccessToken so the next API call fetches a fresh token.
func (c *APIClient) InvalidateToken() {
	c.tokenMu.Lock()
	c.cachedToken = ""
	c.expiresAt = time.Time{}
	c.cacheKey = ""
	c.tokenMu.Unlock()
}

// GetAccessToken returns a valid cached QQBot AccessToken or fetches a fresh one from /app/getAppAccessToken.
func (c *APIClient) GetAccessToken(ctx context.Context, cfg vault.QQBotSettings, forceRefresh bool) (string, error) {
	appID := strings.TrimSpace(cfg.AppID)
	appSecret := strings.TrimSpace(cfg.AppSecret)
	if appID == "" || appSecret == "" {
		return "", fmt.Errorf("QQ 机器人 AppID 与 AppSecret 不能为空")
	}
	tokenEndpoint := cfg.EffectiveTokenBaseURL() + "/app/getAppAccessToken"
	key := tokenEndpoint + "|" + appID + "|" + appSecret

	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if !forceRefresh && c.cacheKey == key && c.cachedToken != "" && c.now().Add(defaultTokenRefreshLead).Before(c.expiresAt) {
		return c.cachedToken, nil
	}

	reqBody, err := json.Marshal(map[string]string{
		"appId":        appID,
		"clientSecret": appSecret,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("构建获取 AccessToken 请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "ServerNeedSafe-QQBot/2.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求 QQ AccessToken 失败: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return "", fmt.Errorf("读取 AccessToken 响应失败: %w", err)
	}

	var parsed AccessTokenResponse
	_ = json.Unmarshal(raw, &parsed)

	// Per QQ Open Platform docs, /app/getAppAccessToken returns business errors via JSON `code`
	// even when HTTP status is 200. Always check `code != 0` first!
	if parsed.Code != 0 {
		msg := strings.TrimSpace(parsed.Message)
		switch parsed.Code {
		case 100001:
			msg = "请求过于频繁，请稍后重试 (" + msg + ")"
		case 100007, 10004:
			msg = "AppID 无效或机器人状态异常，请核对 AppID (" + msg + ")"
		case 100016:
			msg = "AppID 或 AppSecret 不正确，请核对开放平台管理端凭据 (" + msg + ")"
		}
		return "", &APIError{
			StatusCode: resp.StatusCode,
			ErrCode:    parsed.Code,
			Message:    msg,
			RawBody:    truncateRunes(strings.TrimSpace(string(raw)), 300),
		}
	}
	if resp.StatusCode >= 400 {
		return "", &APIError{
			StatusCode: resp.StatusCode,
			Message:    truncateRunes(strings.TrimSpace(string(raw)), 300),
			RawBody:    truncateRunes(strings.TrimSpace(string(raw)), 300),
		}
	}
	tok := strings.TrimSpace(parsed.AccessToken)
	if tok == "" {
		return "", fmt.Errorf("QQ 开放平台未返回有效的 access_token: %s", truncateRunes(strings.TrimSpace(string(raw)), 200))
	}

	ttlSec := int(parsed.ExpiresIn)
	if ttlSec <= 0 {
		ttlSec = 7200
	}
	c.cacheKey = key
	c.cachedToken = tok
	c.expiresAt = c.now().Add(time.Duration(ttlSec) * time.Second)
	return tok, nil
}

// GetGatewayInfo queries GET /gateway/bot (falling back to GET /gateway) to obtain the WSS URL and shard hints.
func (c *APIClient) GetGatewayInfo(ctx context.Context, cfg vault.QQBotSettings) (*GatewayInfo, string, error) {
	token, err := c.GetAccessToken(ctx, cfg, false)
	if err != nil {
		return nil, "", err
	}

	info, err := c.fetchGatewayWithToken(ctx, cfg, token)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.isTokenError() {
			c.InvalidateToken()
			token, err = c.GetAccessToken(ctx, cfg, true)
			if err != nil {
				return nil, "", err
			}
			info, err = c.fetchGatewayWithToken(ctx, cfg, token)
		}
	}
	if err != nil {
		return nil, "", err
	}
	return info, token, nil
}

func (c *APIClient) fetchGatewayWithToken(ctx context.Context, cfg vault.QQBotSettings, token string) (*GatewayInfo, error) {
	apiBase := cfg.EffectiveAPIBaseURL()
	info, err := c.doGetGateway(ctx, apiBase+"/gateway/bot", token)
	if err == nil && strings.TrimSpace(info.URL) != "" {
		return info, nil
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusMethodNotAllowed) {
		info2, err2 := c.doGetGateway(ctx, apiBase+"/gateway", token)
		if err2 == nil && strings.TrimSpace(info2.URL) != "" {
			return info2, nil
		}
		if err2 != nil {
			return nil, err2
		}
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("QQ 网关接口未返回有效的 WebSocket 地址")
}

func (c *APIClient) doGetGateway(ctx context.Context, endpoint, token string) (*GatewayInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "QQBot "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ServerNeedSafe-QQBot/2.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("获取 QQ WebSocket 网关地址失败: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, fmt.Errorf("读取 QQ 网关响应失败: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, parseAPIError(resp.StatusCode, raw)
	}

	var info GatewayInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, fmt.Errorf("解析 QQ 网关地址 JSON 失败: %w", err)
	}
	if strings.TrimSpace(info.URL) == "" {
		var errBody APIErrorResponse
		if json.Unmarshal(raw, &errBody) == nil && errBody.EffectiveCode() != 0 {
			return nil, parseAPIError(resp.StatusCode, raw)
		}
		return nil, fmt.Errorf("QQ 网关返回空 URL: %s", truncateRunes(strings.TrimSpace(string(raw)), 200))
	}
	return &info, nil
}

// SendMessage delivers a notification or passive reply to a QQ c2c user, group, or guild channel.
// It automatically retries once on token expiry and falls back from markdown to plain text if markdown fails.
func (c *APIClient) SendMessage(ctx context.Context, cfg vault.QQBotSettings, req SendMessageRequest) (*SendMessageResponse, error) {
	tt := vault.NormalizeQQBotTargetType(req.TargetType)
	tid := strings.TrimSpace(req.TargetID)
	if tt == "" || tid == "" {
		return nil, fmt.Errorf("无效的 QQ 推送目标类型或 OpenID/ChannelID")
	}

	format := strings.ToLower(strings.TrimSpace(req.Format))
	if format != "markdown" {
		format = "text"
	}
	plainText := strings.TrimSpace(req.PlainText)
	if plainText == "" && strings.TrimSpace(req.Markdown) != "" {
		plainText = MarkdownToQQPlainText(req.Markdown, maxQQMessageRunes)
	} else {
		plainText = truncateRunes(plainText, maxQQMessageRunes)
	}
	markdownText := truncateRunes(strings.TrimSpace(req.Markdown), maxQQMessageRunes)
	if format == "markdown" && markdownText == "" {
		format = "text"
	}
	if plainText == "" && markdownText == "" {
		return nil, fmt.Errorf("消息内容不能为空")
	}

	token, err := c.GetAccessToken(ctx, cfg, false)
	if err != nil {
		return nil, err
	}

	res, err := c.sendOnce(ctx, cfg, token, tt, tid, format, plainText, markdownText, req.MsgID, req.EventID, req.MsgSeq)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.isTokenError() {
			c.InvalidateToken()
			token, err = c.GetAccessToken(ctx, cfg, true)
			if err != nil {
				return nil, err
			}
			res, err = c.sendOnce(ctx, cfg, token, tt, tid, format, plainText, markdownText, req.MsgID, req.EventID, req.MsgSeq)
		}
	}

	// Automatic graceful fallback: if markdown fails (e.g. channel requires invite or markdown syntax rejected),
	// retry once with universal plain text so critical alerts are still delivered!
	if err != nil && format == "markdown" && plainText != "" {
		var apiErr *APIError
		if errors.As(err, &apiErr) && !apiErr.isTokenError() && apiErr.StatusCode < 500 {
			fallbackRes, fbErr := c.sendOnce(ctx, cfg, token, tt, tid, "text", plainText, "", req.MsgID, req.EventID, req.MsgSeq)
			if fbErr == nil {
				fallbackRes.FallbackPlain = true
				return fallbackRes, nil
			}
		}
	}
	return res, err
}

func (c *APIClient) sendOnce(
	ctx context.Context,
	cfg vault.QQBotSettings,
	token string,
	tt vault.QQBotTargetType,
	tid string,
	format string,
	plainText string,
	markdownText string,
	msgID string,
	eventID string,
	msgSeq int,
) (*SendMessageResponse, error) {
	apiBase := cfg.EffectiveAPIBaseURL()
	var endpoint string
	body := map[string]any{}

	switch tt {
	case vault.QQBotTargetC2C:
		endpoint = apiBase + "/v2/users/" + url.PathEscape(tid) + "/messages"
		if format == "markdown" {
			body["msg_type"] = 2
			body["markdown"] = map[string]any{"content": markdownText}
		} else {
			body["msg_type"] = 0
			body["content"] = plainText
		}
		if strings.TrimSpace(msgID) != "" {
			body["msg_id"] = strings.TrimSpace(msgID)
			if msgSeq <= 0 {
				msgSeq = 1
			}
			body["msg_seq"] = msgSeq
		} else if strings.TrimSpace(eventID) != "" {
			body["event_id"] = strings.TrimSpace(eventID)
		}

	case vault.QQBotTargetGroup:
		endpoint = apiBase + "/v2/groups/" + url.PathEscape(tid) + "/messages"
		if format == "markdown" {
			body["msg_type"] = 2
			body["markdown"] = map[string]any{"content": markdownText}
		} else {
			body["msg_type"] = 0
			body["content"] = plainText
		}
		if strings.TrimSpace(msgID) != "" {
			body["msg_id"] = strings.TrimSpace(msgID)
			if msgSeq <= 0 {
				msgSeq = 1
			}
			body["msg_seq"] = msgSeq
		} else if strings.TrimSpace(eventID) != "" {
			body["event_id"] = strings.TrimSpace(eventID)
		}

	case vault.QQBotTargetChannel:
		endpoint = apiBase + "/channels/" + url.PathEscape(tid) + "/messages"
		if format == "markdown" {
			body["markdown"] = map[string]any{"content": markdownText}
		} else {
			body["content"] = plainText
		}
		if strings.TrimSpace(msgID) != "" {
			body["msg_id"] = strings.TrimSpace(msgID)
		} else if strings.TrimSpace(eventID) != "" {
			body["event_id"] = strings.TrimSpace(eventID)
		}
	default:
		return nil, fmt.Errorf("不支持的 QQ 推送目标类型: %s", tt)
	}

	rawReq, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(rawReq))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "QQBot "+token)
	httpReq.Header.Set("Content-Type", "application/json; charset=utf-8")
	httpReq.Header.Set("User-Agent", "ServerNeedSafe-QQBot/2.0")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("调用 QQ 发送消息接口失败: %w", err)
	}
	defer resp.Body.Close()

	rawResp, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, fmt.Errorf("读取 QQ 发送消息响应失败: %w", err)
	}

	// Channel push messages may return HTTP 201/202 with code 304023/304024 meaning queued for platform audit.
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusCreated {
		var errBody APIErrorResponse
		if json.Unmarshal(rawResp, &errBody) == nil {
			code := errBody.EffectiveCode()
			if code == 304023 || code == 304024 {
				return &SendMessageResponse{
					UsedFormat:   format,
					AuditPending: true,
				}, nil
			}
		}
	}

	if resp.StatusCode >= 400 {
		return nil, parseAPIError(resp.StatusCode, rawResp)
	}

	var errBody APIErrorResponse
	if json.Unmarshal(rawResp, &errBody) == nil {
		code := errBody.EffectiveCode()
		if code == 304023 || code == 304024 {
			return &SendMessageResponse{
				UsedFormat:   format,
				AuditPending: true,
			}, nil
		}
		if code != 0 {
			return nil, parseAPIError(resp.StatusCode, rawResp)
		}
	}

	var parsed SendMessageResponse
	_ = json.Unmarshal(rawResp, &parsed)
	parsed.UsedFormat = format
	return &parsed, nil
}

func parseAPIError(statusCode int, raw []byte) *APIError {
	var body APIErrorResponse
	_ = json.Unmarshal(raw, &body)
	msg := strings.TrimSpace(body.Message)
	if msg == "" {
		msg = truncateRunes(strings.TrimSpace(string(raw)), 280)
	}
	return &APIError{
		StatusCode: statusCode,
		ErrCode:    body.EffectiveCode(),
		Message:    msg,
		TraceID:    strings.TrimSpace(body.TraceID),
		RawBody:    truncateRunes(strings.TrimSpace(string(raw)), 320),
	}
}
