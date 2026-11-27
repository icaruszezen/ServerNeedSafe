package aiops

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// ProviderPreset provides one-click templates for popular official, third-party relay, and local LLM services.
type ProviderPreset struct {
	ID              string               `json:"id"`
	Name            string               `json:"name"`
	Protocol        vault.AIProtocol     `json:"protocol"`
	BaseURL         string               `json:"base_url"`
	EndpointMode    vault.AIEndpointMode `json:"endpoint_mode,omitempty"`
	AuthMode        vault.AIAuthMode     `json:"auth_mode,omitempty"`
	DefaultModel    string               `json:"default_model"`
	ContextWindow   int                  `json:"context_window,omitempty"`
	MaxInputTokens  int                  `json:"max_input_tokens,omitempty"`
	MaxOutputTokens int                  `json:"max_output_tokens,omitempty"`
	Description     string               `json:"description"`
}

// BuiltinProviderPresets returns ready-to-use templates for mainstream cloud, 3rd-party compatible relays & local LLMs.
func BuiltinProviderPresets() []ProviderPreset {
	return []ProviderPreset{
		{
			ID:              "openai-responses",
			Name:            "OpenAI 官方 (Responses API)",
			Protocol:        vault.AIProtocolOpenAIResponses,
			BaseURL:         "https://api.openai.com/v1",
			EndpointMode:    vault.AIEndpointModeAuto,
			AuthMode:        vault.AIAuthModeAuto,
			DefaultModel:    "gpt-6.2-sol",
			ContextWindow:   1050000,
			MaxInputTokens:  922000,
			MaxOutputTokens: 128000,
			Description:     "原生 Responses 流式接口，完整适配 GPT-6 / GPT-5 / Codex 推理与工具调用",
		},
		{
			ID:              "anthropic-claude",
			Name:            "Anthropic Claude 原生 / 中转",
			Protocol:        vault.AIProtocolAnthropic,
			BaseURL:         "https://api.anthropic.com",
			EndpointMode:    vault.AIEndpointModeAuto,
			AuthMode:        vault.AIAuthModeAuto,
			DefaultModel:    "claude-sonnet-5-5",
			ContextWindow:   1000000,
			MaxInputTokens:  872000,
			MaxOutputTokens: 128000,
			Description:     "Anthropic Messages 协议，支持 Claude 5.5/4.6 自适应思考与 1M 上下文，兼容中转",
		},
		{
			ID:              "google-gemini",
			Name:            "Google Gemini 原生 / 中转",
			Protocol:        vault.AIProtocolGemini,
			BaseURL:         "https://generativelanguage.googleapis.com/v1beta",
			EndpointMode:    vault.AIEndpointModeAuto,
			AuthMode:        vault.AIAuthModeAuto,
			DefaultModel:    "gemini-4-neon",
			ContextWindow:   1048576,
			MaxInputTokens:  983040,
			MaxOutputTokens: 65536,
			Description:     "Gemini 原生流式协议 (streamGenerateContent)，支持思考等级与多轮签名透传",
		},
		{
			ID:              "deepseek",
			Name:            "DeepSeek 官方接口",
			Protocol:        vault.AIProtocolOpenAI,
			BaseURL:         "https://api.deepseek.com/v1",
			EndpointMode:    vault.AIEndpointModeAuto,
			AuthMode:        vault.AIAuthModeAuto,
			DefaultModel:    "deepseek-v4-pro",
			ContextWindow:   1048576,
			MaxInputTokens:  655360,
			MaxOutputTokens: 393216,
			Description:     "DeepSeek V4 / V3.2 原生思考链透传与工具调用，中文排障性价比极高",
		},
		{
			ID:              "aliyun-bailian",
			Name:            "阿里云百炼 (通义千问)",
			Protocol:        vault.AIProtocolOpenAI,
			BaseURL:         "https://dashscope.aliyuncs.com/compatible-mode/v1",
			EndpointMode:    vault.AIEndpointModeAuto,
			AuthMode:        vault.AIAuthModeAuto,
			DefaultModel:    "qwen4-max",
			ContextWindow:   1000000,
			MaxInputTokens:  737856,
			MaxOutputTokens: 262144,
			Description:     "阿里云百炼兼容接口，支持 qwen4-max / qwen3.8 / deepseek-v4 系列",
		},
		{
			ID:              "openrouter",
			Name:            "OpenRouter 聚合网关",
			Protocol:        vault.AIProtocolOpenAI,
			BaseURL:         "https://openrouter.ai/api/v1",
			EndpointMode:    vault.AIEndpointModeAuto,
			AuthMode:        vault.AIAuthModeAuto,
			DefaultModel:    "anthropic/claude-sonnet-5-5",
			ContextWindow:   1000000,
			MaxInputTokens:  872000,
			MaxOutputTokens: 128000,
			Description:     "一站式聚合 OpenAI / Claude / Gemini / DeepSeek 等数百款最新模型",
		},
		{
			ID:              "openai-compatible-relay",
			Name:            "通用第三方兼容中转 (OneAPI/NewAPI)",
			Protocol:        vault.AIProtocolOpenAI,
			BaseURL:         "https://your-relay.example.com/v1",
			EndpointMode:    vault.AIEndpointModeAuto,
			AuthMode:        vault.AIAuthModeBearer,
			DefaultModel:    "gpt-5.4",
			ContextWindow:   1050000,
			MaxInputTokens:  922000,
			MaxOutputTokens: 128000,
			Description:     "适配各类 OpenAI / Claude / Gemini 兼容第三方中转站，支持自由切换协议与认证头",
		},
		{
			ID:              "siliconflow",
			Name:            "SiliconFlow 硅基流动",
			Protocol:        vault.AIProtocolOpenAI,
			BaseURL:         "https://api.siliconflow.cn/v1",
			EndpointMode:    vault.AIEndpointModeAuto,
			AuthMode:        vault.AIAuthModeAuto,
			DefaultModel:    "deepseek-ai/DeepSeek-V3.2",
			ContextWindow:   163840,
			MaxInputTokens:  98304,
			MaxOutputTokens: 65536,
			Description:     "聚合开源旗舰推理与指令模型，国内直连低延迟",
		},
		{
			ID:              "ollama-local",
			Name:            "本地私有 Ollama / vLLM",
			Protocol:        vault.AIProtocolOpenAI,
			BaseURL:         "http://127.0.0.1:11434/v1",
			EndpointMode:    vault.AIEndpointModeAuto,
			AuthMode:        vault.AIAuthModeNone,
			DefaultModel:    "qwen3:14b",
			ContextWindow:   40960,
			MaxInputTokens:  32768,
			MaxOutputTokens: 8192,
			Description:     "纯内网离线运行，数据零出境，无需填写 API Key",
		},
	}
}

// ToolDefinition describes a callable tool in protocol-neutral JSON Schema form.
type ToolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// LLMToolCall represents a parsed tool invocation returned by an LLM turn.
type LLMToolCall struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// AssistantTurn captures the completed text, reasoning, tool calls, protocol round-trip state, and real usage.
type AssistantTurn struct {
	Content          string
	ReasoningContent string
	ToolCalls        []LLMToolCall
	ProviderState    *vault.AIMessageMeta
	Usage            *vault.AITokenUsage
}

// StreamCallbacks receives incremental text and reasoning chunks during SSE streaming.
type StreamCallbacks struct {
	OnTextDelta      func(textChunk string)
	OnReasoningDelta func(reasoningChunk string)
}

// TestConnectionResult carries detailed streaming latency and preview info from connectivity checks.
type TestConnectionResult struct {
	LatencyMs        int64               `json:"latency_ms"`
	FirstTokenMs     int64               `json:"first_token_ms,omitempty"`
	Reply            string              `json:"reply"`
	ReasoningPreview string              `json:"reasoning_preview,omitempty"`
	Protocol         vault.AIProtocol    `json:"protocol"`
	Model            string              `json:"model"`
	Usage            *vault.AITokenUsage `json:"usage,omitempty"`
}

// LLMClient executes strictly streaming requests against OpenAI Chat Completions,
// OpenAI Responses API, Anthropic Messages, and Google Gemini endpoints.
type LLMClient struct {
	transport       HTTPTransport
	catalogProvider func() *vault.AIModelCatalogCache
}

func NewLLMClient() *LLMClient {
	return &LLMClient{
		transport: newDefaultHTTPTransport(),
	}
}

// SetCatalogProvider attaches an optional cache reader so LLMClient uses synced online model specs.
func (c *LLMClient) SetCatalogProvider(fn func() *vault.AIModelCatalogCache) {
	if c != nil {
		c.catalogProvider = fn
	}
}

// Transport exposes the underlying HTTPTransport for shared webhook delivery and catalog sync.
func (c *LLMClient) Transport() HTTPTransport {
	if c == nil || c.transport == nil {
		return newDefaultHTTPTransport()
	}
	return c.transport
}

func (c *LLMClient) lookupSpec(prov vault.AIProviderConfig) ModelSpec {
	var cached *vault.AIModelCatalogCache
	if c != nil && c.catalogProvider != nil {
		cached = c.catalogProvider()
	}
	return LookupModelSpec(prov.Model, vault.NormalizeAIProtocol(prov.Protocol), cached)
}

// TestConnection sends a minimal streaming ping message to verify endpoint reachability, credentials, and latency.
func (c *LLMClient) TestConnection(ctx context.Context, prov vault.AIProviderConfig) (int64, string, error) {
	res, err := c.TestConnectionDetailed(ctx, prov)
	if err != nil {
		return 0, "", err
	}
	return res.LatencyMs, res.Reply, nil
}

// TestConnectionDetailed runs a real streaming connectivity check using the provider's configured protocol
// and parameters WITHOUT artificially shrinking max_output_tokens (which would starve thinking/reasoning models).
func (c *LLMClient) TestConnectionDetailed(ctx context.Context, prov vault.AIProviderConfig) (*TestConnectionResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	start := time.Now()
	var firstTokenMs int64
	markFirst := func() {
		if firstTokenMs == 0 {
			firstTokenMs = max(int64(1), time.Since(start).Milliseconds())
		}
	}

	msgs := []vault.AIChatMessage{
		{
			Role:    "user",
			Content: "请仅回复“连接正常”四个字用于连通性自检。",
		},
	}

	// Keep the user's configured max_output_tokens intact (or unset/model default);
	// never clamp to tiny values like 64 which break reasoning/thinking models!
	turn, err := c.StreamChat(ctx, prov, "你是 ServerNeedSafe 连通性测试助手。", msgs, nil, StreamCallbacks{
		OnTextDelta: func(string) {
			markFirst()
		},
		OnReasoningDelta: func(string) {
			markFirst()
		},
	})
	if err != nil {
		return nil, err
	}

	latency := max(int64(1), time.Since(start).Milliseconds())
	preview := strings.TrimSpace(turn.Content)
	reasoningPreview := strings.TrimSpace(turn.ReasoningContent)
	if len([]rune(reasoningPreview)) > 160 {
		reasoningPreview = string([]rune(reasoningPreview)[:160]) + "..."
	}
	if preview == "" {
		if reasoningPreview != "" {
			preview = "连接正常（模型返回了思考流，建议调大最大输出 Tokens 以输出正文）"
		} else {
			preview = "连接成功"
		}
	}
	return &TestConnectionResult{
		LatencyMs:        latency,
		FirstTokenMs:     firstTokenMs,
		Reply:            preview,
		ReasoningPreview: reasoningPreview,
		Protocol:         vault.NormalizeAIProtocol(prov.Protocol),
		Model:            prov.Model,
		Usage:            turn.Usage,
	}, nil
}

// StreamChat invokes the configured protocol strictly in streaming SSE mode with automatic model parameter adaptation.
func (c *LLMClient) StreamChat(
	ctx context.Context,
	prov vault.AIProviderConfig,
	systemPrompt string,
	history []vault.AIChatMessage,
	tools []ToolDefinition,
	cb StreamCallbacks,
) (*AssistantTurn, error) {
	proto := vault.NormalizeAIProtocol(prov.Protocol)
	spec := c.lookupSpec(prov)
	switch proto {
	case vault.AIProtocolOpenAIResponses:
		return c.streamOpenAIResponses(ctx, prov, spec, systemPrompt, history, tools, cb)
	case vault.AIProtocolAnthropic:
		return c.streamAnthropic(ctx, prov, spec, systemPrompt, history, tools, cb)
	case vault.AIProtocolGemini:
		return c.streamGemini(ctx, prov, spec, systemPrompt, history, tools, cb)
	default:
		return c.streamOpenAIChat(ctx, prov, spec, systemPrompt, history, tools, cb)
	}
}

// --- Shared Endpoint Resolution, Auth, Custom Headers, Extra Body Merge & Error Handling ---

var versionPathSuffixRe = regexp.MustCompile(`(?i)/(v[0-9]+(alpha|beta)?|openai|compatible-mode/v[0-9]+)$`)

func resolveChatEndpoint(prov vault.AIProviderConfig, proto vault.AIProtocol) string {
	raw := strings.TrimSpace(prov.BaseURL)
	if vault.NormalizeAIEndpointMode(prov.EndpointMode) == vault.AIEndpointModeExact {
		if proto == vault.AIProtocolGemini {
			return ensureQueryParam(raw, "alt", "sse")
		}
		return raw
	}

	u := strings.TrimRight(raw, "/")
	switch proto {
	case vault.AIProtocolOpenAI:
		if strings.HasSuffix(u, "/chat/completions") {
			return u
		}
		if versionPathSuffixRe.MatchString(u) {
			return u + "/chat/completions"
		}
		return u + "/v1/chat/completions"

	case vault.AIProtocolOpenAIResponses:
		if strings.HasSuffix(u, "/responses") {
			return u
		}
		if strings.HasSuffix(u, "/chat/completions") {
			return strings.TrimSuffix(u, "/chat/completions") + "/responses"
		}
		if versionPathSuffixRe.MatchString(u) {
			return u + "/responses"
		}
		return u + "/v1/responses"

	case vault.AIProtocolAnthropic:
		if strings.HasSuffix(u, "/v1/messages") || strings.HasSuffix(u, "/messages") {
			return u
		}
		if versionPathSuffixRe.MatchString(u) {
			return u + "/messages"
		}
		return u + "/v1/messages"

	case vault.AIProtocolGemini:
		model := strings.TrimPrefix(strings.TrimSpace(prov.Model), "models/")
		if strings.Contains(u, ":streamGenerateContent") {
			return ensureQueryParam(u, "alt", "sse")
		}
		if strings.Contains(u, ":generateContent") {
			rewritten := strings.Replace(u, ":generateContent", ":streamGenerateContent", 1)
			return ensureQueryParam(rewritten, "alt", "sse")
		}
		if strings.HasSuffix(u, "/models") {
			return ensureQueryParam(u+"/"+url.PathEscape(model)+":streamGenerateContent", "alt", "sse")
		}
		if versionPathSuffixRe.MatchString(u) {
			return ensureQueryParam(u+"/models/"+url.PathEscape(model)+":streamGenerateContent", "alt", "sse")
		}
		return ensureQueryParam(u+"/v1beta/models/"+url.PathEscape(model)+":streamGenerateContent", "alt", "sse")

	default:
		return resolveOpenAIEndpoint(u)
	}
}

func resolveOpenAIEndpoint(baseURL string) string {
	u := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if strings.HasSuffix(u, "/chat/completions") {
		return u
	}
	if versionPathSuffixRe.MatchString(u) {
		return u + "/chat/completions"
	}
	return u + "/v1/chat/completions"
}

func resolveAnthropicEndpoint(baseURL string) string {
	u := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if strings.HasSuffix(u, "/v1/messages") || strings.HasSuffix(u, "/messages") {
		return u
	}
	if versionPathSuffixRe.MatchString(u) {
		return u + "/messages"
	}
	return u + "/v1/messages"
}

func resolveModelsEndpoint(baseURL string, proto vault.AIProtocol) string {
	u := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	// Strip query string if caller pasted a full streaming URL
	if parsed, err := url.Parse(u); err == nil && parsed.RawQuery != "" {
		parsed.RawQuery = ""
		u = strings.TrimRight(parsed.String(), "/")
	}

	switch proto {
	case vault.AIProtocolGemini:
		if idx := strings.Index(u, "/models/"); idx > 0 {
			return u[:idx] + "/models"
		}
		if strings.HasSuffix(u, "/models") {
			return u
		}
		if versionPathSuffixRe.MatchString(u) {
			return u + "/models"
		}
		return u + "/v1beta/models"

	case vault.AIProtocolAnthropic:
		u = strings.TrimSuffix(u, "/messages")
		if strings.HasSuffix(u, "/models") {
			return u
		}
		if versionPathSuffixRe.MatchString(u) {
			return u + "/models"
		}
		return u + "/v1/models"

	default: // openai / openai_responses
		u = strings.TrimSuffix(u, "/chat/completions")
		u = strings.TrimSuffix(u, "/responses")
		if strings.HasSuffix(u, "/models") {
			return u
		}
		if versionPathSuffixRe.MatchString(u) {
			return u + "/models"
		}
		return u + "/v1/models"
	}
}

func ensureQueryParam(rawURL, key, val string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		if strings.Contains(rawURL, "?") {
			if strings.Contains(rawURL, key+"=") {
				return rawURL
			}
			return rawURL + "&" + url.QueryEscape(key) + "=" + url.QueryEscape(val)
		}
		return rawURL + "?" + url.QueryEscape(key) + "=" + url.QueryEscape(val)
	}
	q := parsed.Query()
	if q.Get(key) == "" {
		q.Set(key, val)
		parsed.RawQuery = q.Encode()
	}
	return parsed.String()
}

func applyAuthAndHeaders(prov vault.AIProviderConfig, proto vault.AIProtocol, endpoint string, headers map[string]string) string {
	apiKey := strings.TrimSpace(prov.APIKey)
	authMode := vault.NormalizeAIAuthMode(prov.AuthMode)
	if authMode == vault.AIAuthModeAuto {
		switch proto {
		case vault.AIProtocolAnthropic:
			authMode = vault.AIAuthModeXAPIKey
		case vault.AIProtocolGemini:
			authMode = vault.AIAuthModeXGoogAPIKey
		default:
			authMode = vault.AIAuthModeBearer
		}
	}

	if apiKey != "" {
		switch authMode {
		case vault.AIAuthModeBearer:
			headers["Authorization"] = "Bearer " + apiKey
		case vault.AIAuthModeXAPIKey:
			headers["x-api-key"] = apiKey
		case vault.AIAuthModeXGoogAPIKey:
			headers["x-goog-api-key"] = apiKey
		case vault.AIAuthModeQueryKey:
			endpoint = ensureQueryParam(endpoint, "key", apiKey)
		case vault.AIAuthModeNone:
			// Explicitly omit auth header/query
		}
	}

	// Custom headers always apply last so users can override any header without restriction.
	for _, h := range prov.CustomHeaders {
		k := strings.TrimSpace(h.Key)
		if k == "" {
			continue
		}
		headers[k] = h.Value
	}
	return endpoint
}

func sanitizeURLError(err error, apiKey string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	key := strings.TrimSpace(apiKey)
	if key != "" {
		msg = strings.ReplaceAll(msg, key, "***")
		msg = strings.ReplaceAll(msg, url.QueryEscape(key), "***")
	}
	return fmt.Errorf("%s", msg)
}

// mergeExtraBodyJSON applies an RFC 7396 JSON Merge Patch from rawExtra into dst.
// Nested objects merge recursively; explicit null values delete keys; scalars/arrays replace directly.
func mergeExtraBodyJSON(dst map[string]any, rawExtra string) error {
	trimmed := strings.TrimSpace(rawExtra)
	if trimmed == "" {
		return nil
	}
	var patch map[string]any
	if err := json.Unmarshal([]byte(trimmed), &patch); err != nil {
		return fmt.Errorf("自定义扩展请求体 JSON 无效: %w", err)
	}
	if patch == nil {
		return nil
	}
	deepMergeMap(dst, patch)
	return nil
}

func deepMergeMap(dst, patch map[string]any) {
	for k, v := range patch {
		if v == nil {
			delete(dst, k)
			continue
		}
		if patchSub, ok := v.(map[string]any); ok {
			if dstSub, ok2 := dst[k].(map[string]any); ok2 && dstSub != nil {
				deepMergeMap(dstSub, patchSub)
				continue
			}
			// Clone patchSub into a fresh map so we don't alias caller structures
			fresh := make(map[string]any, len(patchSub))
			deepMergeMap(fresh, patchSub)
			dst[k] = fresh
			continue
		}
		dst[k] = v
	}
}

func validateStrictStreamMeta(meta *StreamResponseMeta, protocolLabel string) error {
	if meta == nil {
		return fmt.Errorf("%s 接口未返回有效响应", protocolLabel)
	}
	if meta.StatusCode >= 400 {
		return fmt.Errorf("%s 接口返回 HTTP %d: %s", protocolLabel, meta.StatusCode, extractProviderErrMsg(meta.RawBody))
	}
	if !meta.IsSSE {
		if errMsg := extractExplicitErrorField(meta.RawBody); errMsg != "" {
			return fmt.Errorf("%s 接口返回错误: %s", protocolLabel, errMsg)
		}
		return fmt.Errorf("%s 接口返回了非流式响应 (Content-Type: %s)，当前强制仅使用流式 SSE 请求，请检查接口地址或确认该网关支持流式响应", protocolLabel, nonEmpty(meta.ContentType, "未知"))
	}
	return nil
}

func extractExplicitErrorField(raw []byte) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return ""
	}
	// Handle Gemini array error: [{"error": {"message": "..."}}]
	if strings.HasPrefix(trimmed, "[") {
		var arr []struct {
			Error any `json:"error"`
		}
		if json.Unmarshal(raw, &arr) == nil {
			for _, item := range arr {
				if msg := parseErrorValue(item.Error); msg != "" {
					return msg
				}
			}
		}
	}
	var parsed struct {
		Error   any    `json:"error"`
		Message string `json:"message"`
		Detail  string `json:"detail"`
	}
	if json.Unmarshal(raw, &parsed) == nil {
		if msg := parseErrorValue(parsed.Error); msg != "" {
			return msg
		}
	}
	return ""
}

func parseErrorValue(val any) string {
	if val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return strings.TrimSpace(v)
	case map[string]any:
		if msg, ok := v["message"].(string); ok && strings.TrimSpace(msg) != "" {
			return strings.TrimSpace(msg)
		}
		if msg, ok := v["detail"].(string); ok && strings.TrimSpace(msg) != "" {
			return strings.TrimSpace(msg)
		}
		if typ, ok := v["type"].(string); ok && strings.TrimSpace(typ) != "" {
			return strings.TrimSpace(typ)
		}
	}
	return ""
}

func extractProviderErrMsg(raw []byte) string {
	if msg := extractExplicitErrorField(raw); msg != "" {
		return msg
	}
	var parsed struct {
		Message string `json:"message"`
		Detail  string `json:"detail"`
	}
	if json.Unmarshal(raw, &parsed) == nil {
		if strings.TrimSpace(parsed.Message) != "" {
			return strings.TrimSpace(parsed.Message)
		}
		if strings.TrimSpace(parsed.Detail) != "" {
			return strings.TrimSpace(parsed.Detail)
		}
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 420 {
		s = TruncateUTF8Bytes(s, 420) + "..."
	}
	if s == "" {
		return "未知错误"
	}
	return s
}

func finalizeUsage(u *vault.AITokenUsage) *vault.AITokenUsage {
	if u == nil {
		return nil
	}
	if u.InputTokens == 0 && u.OutputTokens == 0 && u.ReasoningTokens == 0 && u.CachedInputTokens == 0 && u.TotalTokens == 0 {
		return nil
	}
	if u.TotalTokens == 0 {
		u.TotalTokens = u.InputTokens + u.OutputTokens
	}
	return u
}
