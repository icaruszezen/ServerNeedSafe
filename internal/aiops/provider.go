package aiops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// ProviderPreset provides one-click templates for popular LLM vendors.
type ProviderPreset struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Protocol     vault.AIProtocol `json:"protocol"`
	BaseURL      string           `json:"base_url"`
	DefaultModel string           `json:"default_model"`
	Description  string           `json:"description"`
}

// BuiltinProviderPresets returns ready-to-use templates for mainstream cloud & local LLM services.
func BuiltinProviderPresets() []ProviderPreset {
	return []ProviderPreset{
		{
			ID:           "deepseek",
			Name:         "DeepSeek 官方接口",
			Protocol:     vault.AIProtocolOpenAI,
			BaseURL:      "https://api.deepseek.com/v1",
			DefaultModel: "deepseek-chat",
			Description:  "原生兼容 OpenAI Tool Calling，中文排障性价比极高",
		},
		{
			ID:           "aliyun-bailian",
			Name:         "阿里云百炼 (通义千问)",
			Protocol:     vault.AIProtocolOpenAI,
			BaseURL:      "https://dashscope.aliyuncs.com/compatible-mode/v1",
			DefaultModel: "qwen-max",
			Description:  "阿里云百炼兼容接口，支持 qwen-max / qwen-plus / deepseek 系列",
		},
		{
			ID:           "anthropic-claude",
			Name:         "Anthropic Claude 原生",
			Protocol:     vault.AIProtocolAnthropic,
			BaseURL:      "https://api.anthropic.com",
			DefaultModel: "claude-sonnet-4-5",
			Description:  "原生 Anthropic Messages 协议，擅长复杂 Shell 诊断与配置加固",
		},
		{
			ID:           "openai",
			Name:         "OpenAI 官方接口",
			Protocol:     vault.AIProtocolOpenAI,
			BaseURL:      "https://api.openai.com/v1",
			DefaultModel: "gpt-4.1",
			Description:  "标准 OpenAI Chat Completions 接口",
		},
		{
			ID:           "siliconflow",
			Name:         "SiliconFlow 硅基流动",
			Protocol:     vault.AIProtocolOpenAI,
			BaseURL:      "https://api.siliconflow.cn/v1",
			DefaultModel: "Qwen/Qwen3-235B-A22B",
			Description:  "聚合多种开源旗舰推理与指令模型",
		},
		{
			ID:           "ollama-local",
			Name:         "本地私有 Ollama",
			Protocol:     vault.AIProtocolOpenAI,
			BaseURL:      "http://127.0.0.1:11434/v1",
			DefaultModel: "qwen3:14b",
			Description:  "纯内网离线运行，数据零出境，无需填写 API Key",
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

// AssistantTurn captures the completed text and/or tool calls of one LLM invocation.
type AssistantTurn struct {
	Content   string
	ToolCalls []LLMToolCall
}

// LLMClient executes streaming/non-streaming requests against OpenAI-compatible and Anthropic endpoints.
type LLMClient struct {
	transport HTTPTransport
}

func NewLLMClient() *LLMClient {
	return &LLMClient{
		transport: newDefaultHTTPTransport(),
	}
}

// Transport exposes the underlying HTTPTransport for shared webhook delivery.
func (c *LLMClient) Transport() HTTPTransport {
	if c == nil || c.transport == nil {
		return newDefaultHTTPTransport()
	}
	return c.transport
}

// TestConnection sends a minimal ping message to verify endpoint reachability, credentials, and latency.
func (c *LLMClient) TestConnection(ctx context.Context, prov vault.AIProviderConfig) (int64, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	start := time.Now()
	msgs := []vault.AIChatMessage{
		{
			Role:    "user",
			Content: "请仅回复“连接正常”四个字用于连通性自检。",
		},
	}
	prov.MaxTokens = 64
	turn, err := c.StreamChat(ctx, prov, "你是 ServerNeedSafe 连通性测试助手。", msgs, nil, nil)
	if err != nil {
		return 0, "", err
	}
	latency := time.Since(start).Milliseconds()
	if latency <= 0 {
		latency = 1
	}
	preview := strings.TrimSpace(turn.Content)
	if preview == "" {
		preview = "连接成功"
	}
	return latency, preview, nil
}

// StreamChat invokes either OpenAI Chat Completions or Anthropic Messages with SSE streaming and tool calling.
func (c *LLMClient) StreamChat(
	ctx context.Context,
	prov vault.AIProviderConfig,
	systemPrompt string,
	history []vault.AIChatMessage,
	tools []ToolDefinition,
	onDelta func(textChunk string),
) (*AssistantTurn, error) {
	switch prov.Protocol {
	case vault.AIProtocolAnthropic:
		return c.streamAnthropic(ctx, prov, systemPrompt, history, tools, onDelta)
	default:
		return c.streamOpenAI(ctx, prov, systemPrompt, history, tools, onDelta)
	}
}

// --- OpenAI Chat Completions Compatible Protocol ---

func resolveOpenAIEndpoint(baseURL string) string {
	u := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if strings.HasSuffix(u, "/chat/completions") {
		return u
	}
	if strings.HasSuffix(u, "/v1") || strings.Contains(u, "/compatible-mode/v1") || strings.HasSuffix(u, "/openai") {
		return u + "/chat/completions"
	}
	return u + "/v1/chat/completions"
}

func (c *LLMClient) streamOpenAI(
	ctx context.Context,
	prov vault.AIProviderConfig,
	systemPrompt string,
	history []vault.AIChatMessage,
	tools []ToolDefinition,
	onDelta func(string),
) (*AssistantTurn, error) {
	messages := make([]map[string]any, 0, len(history)+1)
	if strings.TrimSpace(systemPrompt) != "" {
		messages = append(messages, map[string]any{
			"role":    "system",
			"content": systemPrompt,
		})
	}

	for _, m := range history {
		switch m.Role {
		case "user":
			messages = append(messages, map[string]any{
				"role":    "user",
				"content": m.Content,
			})
		case "assistant":
			item := map[string]any{
				"role": "assistant",
			}
			if m.Content != "" || len(m.ToolCalls) == 0 {
				item["content"] = m.Content
			}
			if len(m.ToolCalls) > 0 {
				tcs := make([]map[string]any, len(m.ToolCalls))
				for i, tc := range m.ToolCalls {
					args := tc.Arguments
					if strings.TrimSpace(args) == "" {
						args = "{}"
					}
					tcs[i] = map[string]any{
						"id":   tc.ID,
						"type": "function",
						"function": map[string]any{
							"name":      tc.Name,
							"arguments": args,
						},
					}
				}
				item["tool_calls"] = tcs
			}
			messages = append(messages, item)
		case "tool":
			messages = append(messages, map[string]any{
				"role":         "tool",
				"tool_call_id": m.ToolCallID,
				"content":      m.Content,
			})
		}
	}

	maxTok := prov.MaxTokens
	if maxTok <= 0 {
		maxTok = 4096
	}

	payload := map[string]any{
		"model":      prov.Model,
		"messages":   messages,
		"max_tokens": maxTok,
		"stream":     true,
	}
	if len(tools) > 0 {
		oaTools := make([]map[string]any, len(tools))
		for i, td := range tools {
			oaTools[i] = map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        td.Name,
					"description": td.Description,
					"parameters":  td.Parameters,
				},
			}
		}
		payload["tools"] = oaTools
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "text/event-stream, application/json",
	}
	if strings.TrimSpace(prov.APIKey) != "" {
		headers["Authorization"] = "Bearer " + strings.TrimSpace(prov.APIKey)
	}

	type partialCall struct {
		id   string
		name string
		args strings.Builder
	}
	var contentBuf strings.Builder
	callByIdx := make(map[int]*partialCall)
	maxIdx := -1
	var streamErrMsg string

	endpoint := resolveOpenAIEndpoint(prov.BaseURL)
	meta, err := c.Transport().PostStream(ctx, endpoint, headers, bodyBytes, func(rawLine string) bool {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "data:") {
			return true
		}
		dataStr := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if dataStr == "" {
			return true
		}
		if dataStr == "[DONE]" {
			return false
		}

		var chunk struct {
			Error   any `json:"error"`
			Choices []struct {
				Delta struct {
					Content   string `json:"content"`
					ToolCalls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal([]byte(dataStr), &chunk) != nil {
			return true
		}
		if chunk.Error != nil {
			streamErrMsg = extractProviderErrMsg([]byte(dataStr))
			return false
		}
		for _, ch := range chunk.Choices {
			if ch.Delta.Content != "" {
				contentBuf.WriteString(ch.Delta.Content)
				if onDelta != nil {
					onDelta(ch.Delta.Content)
				}
			}
			for _, tc := range ch.Delta.ToolCalls {
				pc, ok := callByIdx[tc.Index]
				if !ok {
					pc = &partialCall{}
					callByIdx[tc.Index] = pc
					if tc.Index > maxIdx {
						maxIdx = tc.Index
					}
				}
				if tc.ID != "" {
					pc.id = tc.ID
				}
				if tc.Function.Name != "" {
					pc.name += tc.Function.Name
				}
				if tc.Function.Arguments != "" {
					pc.args.WriteString(tc.Function.Arguments)
				}
			}
		}
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("请求大模型接口失败: %w", err)
	}
	if meta.StatusCode >= 400 {
		return nil, fmt.Errorf("模型接口返回 HTTP %d: %s", meta.StatusCode, extractProviderErrMsg(meta.RawBody))
	}
	if streamErrMsg != "" {
		return nil, fmt.Errorf("模型流式接口返回错误: %s", streamErrMsg)
	}
	if !strings.Contains(strings.ToLower(meta.ContentType), "text/event-stream") {
		return parseOpenAINonStream(bytes.NewReader(meta.RawBody), onDelta)
	}

	turn := &AssistantTurn{
		Content: contentBuf.String(),
	}
	fallbackPrefix := uuid.NewString()[:8]
	for i := 0; i <= maxIdx; i++ {
		if pc, ok := callByIdx[i]; ok && pc.name != "" {
			id := pc.id
			if id == "" {
				id = fmt.Sprintf("call_%s_%d", fallbackPrefix, i+1)
			}
			args := strings.TrimSpace(pc.args.String())
			if args == "" {
				args = "{}"
			}
			turn.ToolCalls = append(turn.ToolCalls, LLMToolCall{
				ID:        id,
				Name:      pc.name,
				Arguments: args,
			})
		}
	}
	return turn, nil
}

func parseOpenAINonStream(r io.Reader, onDelta func(string)) (*AssistantTurn, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 4*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("读取大模型响应失败: %w", err)
	}
	var resp struct {
		Error   any `json:"error"`
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("解析大模型响应失败: %w", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("模型接口返回错误: %s", extractProviderErrMsg(raw))
	}
	if len(resp.Choices) == 0 {
		return &AssistantTurn{}, nil
	}
	msg := resp.Choices[0].Message
	if msg.Content != "" && onDelta != nil {
		onDelta(msg.Content)
	}
	turn := &AssistantTurn{Content: msg.Content}
	fallbackPrefix := uuid.NewString()[:8]
	for i, tc := range msg.ToolCalls {
		id := tc.ID
		if id == "" {
			id = fmt.Sprintf("call_%s_%d", fallbackPrefix, i+1)
		}
		args := strings.TrimSpace(tc.Function.Arguments)
		if args == "" {
			args = "{}"
		}
		turn.ToolCalls = append(turn.ToolCalls, LLMToolCall{
			ID:        id,
			Name:      tc.Function.Name,
			Arguments: args,
		})
	}
	return turn, nil
}

// --- Anthropic Messages Native Protocol ---

func resolveAnthropicEndpoint(baseURL string) string {
	u := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if strings.HasSuffix(u, "/v1/messages") || strings.HasSuffix(u, "/messages") {
		return u
	}
	if strings.HasSuffix(u, "/v1") {
		return u + "/messages"
	}
	return u + "/v1/messages"
}

func buildAnthropicMessages(history []vault.AIChatMessage) []map[string]any {
	var anthMessages []map[string]any

	toBlocks := func(content any) []map[string]any {
		switch v := content.(type) {
		case []map[string]any:
			return v
		case string:
			if strings.TrimSpace(v) == "" {
				return nil
			}
			return []map[string]any{{"type": "text", "text": v}}
		default:
			return nil
		}
	}

	appendMsg := func(role string, content any) {
		if len(anthMessages) > 0 && anthMessages[len(anthMessages)-1]["role"] == role {
			prevBlocks := toBlocks(anthMessages[len(anthMessages)-1]["content"])
			nextBlocks := toBlocks(content)
			merged := append(prevBlocks, nextBlocks...)
			if len(merged) > 0 {
				anthMessages[len(anthMessages)-1]["content"] = merged
			}
			return
		}
		anthMessages = append(anthMessages, map[string]any{
			"role":    role,
			"content": content,
		})
	}

	for i := 0; i < len(history); i++ {
		m := history[i]
		switch m.Role {
		case "user":
			if strings.TrimSpace(m.Content) == "" {
				continue
			}
			appendMsg("user", m.Content)
		case "assistant":
			var blocks []map[string]any
			if strings.TrimSpace(m.Content) != "" {
				blocks = append(blocks, map[string]any{
					"type": "text",
					"text": m.Content,
				})
			}
			for _, tc := range m.ToolCalls {
				var parsedInput any = map[string]any{}
				if strings.TrimSpace(tc.Arguments) != "" {
					_ = json.Unmarshal([]byte(tc.Arguments), &parsedInput)
				}
				blocks = append(blocks, map[string]any{
					"type":  "tool_use",
					"id":    tc.ID,
					"name":  tc.Name,
					"input": parsedInput,
				})
			}
			if len(blocks) > 0 {
				appendMsg("assistant", blocks)
			}
		case "tool":
			var resultBlocks []map[string]any
			for ; i < len(history) && history[i].Role == "tool"; i++ {
				tm := history[i]
				resultBlocks = append(resultBlocks, map[string]any{
					"type":        "tool_result",
					"tool_use_id": tm.ToolCallID,
					"content":     tm.Content,
					"is_error":    tm.IsError,
				})
			}
			i--
			if len(resultBlocks) > 0 {
				appendMsg("user", resultBlocks)
			}
		}
	}

	// Anthropic Messages API requires the first message to have role "user".
	for len(anthMessages) > 0 && anthMessages[0]["role"] != "user" {
		anthMessages = anthMessages[1:]
	}
	return anthMessages
}

func (c *LLMClient) streamAnthropic(
	ctx context.Context,
	prov vault.AIProviderConfig,
	systemPrompt string,
	history []vault.AIChatMessage,
	tools []ToolDefinition,
	onDelta func(string),
) (*AssistantTurn, error) {
	anthMessages := buildAnthropicMessages(history)

	maxTok := prov.MaxTokens
	if maxTok <= 0 {
		maxTok = 4096
	}
	payload := map[string]any{
		"model":      prov.Model,
		"max_tokens": maxTok,
		"messages":   anthMessages,
		"stream":     true,
	}
	if strings.TrimSpace(systemPrompt) != "" {
		payload["system"] = systemPrompt
	}
	if len(tools) > 0 {
		anthTools := make([]map[string]any, len(tools))
		for i, td := range tools {
			anthTools[i] = map[string]any{
				"name":         td.Name,
				"description":  td.Description,
				"input_schema": td.Parameters,
			}
		}
		payload["tools"] = anthTools
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	headers := map[string]string{
		"Content-Type":                              "application/json",
		"Accept":                                    "text/event-stream, application/json",
		"anthropic-version":                         "2023-06-01",
		"anthropic-dangerous-direct-browser-access": "true",
	}
	if strings.TrimSpace(prov.APIKey) != "" {
		headers["x-api-key"] = strings.TrimSpace(prov.APIKey)
	}

	type anthBlock struct {
		kind string
		id   string
		name string
		json strings.Builder
	}
	var contentBuf strings.Builder
	blocks := make(map[int]*anthBlock)
	maxIdx := -1
	var streamErrMsg string

	endpoint := resolveAnthropicEndpoint(prov.BaseURL)
	meta, err := c.Transport().PostStream(ctx, endpoint, headers, bodyBytes, func(rawLine string) bool {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "data:") {
			return true
		}
		dataStr := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if dataStr == "" {
			return true
		}
		var ev struct {
			Type         string `json:"type"`
			Index        int    `json:"index"`
			Error        any    `json:"error"`
			ContentBlock struct {
				Type  string          `json:"type"`
				ID    string          `json:"id"`
				Name  string          `json:"name"`
				Text  string          `json:"text"`
				Input json.RawMessage `json:"input"`
			} `json:"content_block"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
			} `json:"delta"`
		}
		if json.Unmarshal([]byte(dataStr), &ev) != nil {
			return true
		}
		switch ev.Type {
		case "error":
			streamErrMsg = extractProviderErrMsg([]byte(dataStr))
			return false
		case "content_block_start":
			b := &anthBlock{
				kind: ev.ContentBlock.Type,
				id:   ev.ContentBlock.ID,
				name: ev.ContentBlock.Name,
			}
			if ev.ContentBlock.Type == "text" && ev.ContentBlock.Text != "" {
				contentBuf.WriteString(ev.ContentBlock.Text)
				if onDelta != nil {
					onDelta(ev.ContentBlock.Text)
				}
			}
			if ev.ContentBlock.Type == "tool_use" && len(ev.ContentBlock.Input) > 0 && string(ev.ContentBlock.Input) != "{}" {
				b.json.Write(ev.ContentBlock.Input)
			}
			blocks[ev.Index] = b
			if ev.Index > maxIdx {
				maxIdx = ev.Index
			}
		case "content_block_delta":
			if ev.Delta.Type == "text_delta" && ev.Delta.Text != "" {
				contentBuf.WriteString(ev.Delta.Text)
				if onDelta != nil {
					onDelta(ev.Delta.Text)
				}
			} else if ev.Delta.Type == "input_json_delta" && ev.Delta.PartialJSON != "" {
				if b, ok := blocks[ev.Index]; ok {
					b.json.WriteString(ev.Delta.PartialJSON)
				}
			}
		case "message_stop":
			return false
		}
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("请求 Anthropic 接口失败: %w", err)
	}
	if meta.StatusCode >= 400 {
		return nil, fmt.Errorf("Anthropic 接口返回 HTTP %d: %s", meta.StatusCode, extractProviderErrMsg(meta.RawBody))
	}
	if streamErrMsg != "" {
		return nil, fmt.Errorf("Anthropic 流式接口返回错误: %s", streamErrMsg)
	}
	if !strings.Contains(strings.ToLower(meta.ContentType), "text/event-stream") {
		return parseAnthropicNonStream(bytes.NewReader(meta.RawBody), onDelta)
	}

	turn := &AssistantTurn{Content: contentBuf.String()}
	fallbackPrefix := uuid.NewString()[:8]
	for i := 0; i <= maxIdx; i++ {
		if b, ok := blocks[i]; ok && b.kind == "tool_use" && b.name != "" {
			id := b.id
			if id == "" {
				id = fmt.Sprintf("toolu_%s_%d", fallbackPrefix, i+1)
			}
			args := strings.TrimSpace(b.json.String())
			if args == "" {
				args = "{}"
			}
			turn.ToolCalls = append(turn.ToolCalls, LLMToolCall{
				ID:        id,
				Name:      b.name,
				Arguments: args,
			})
		}
	}
	return turn, nil
}

func parseAnthropicNonStream(r io.Reader, onDelta func(string)) (*AssistantTurn, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 4*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("读取 Anthropic 响应失败: %w", err)
	}
	var resp struct {
		Type    string `json:"type"`
		Error   any    `json:"error"`
		Content []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("解析 Anthropic 响应失败: %w", err)
	}
	if resp.Type == "error" || resp.Error != nil {
		return nil, fmt.Errorf("Anthropic 接口返回错误: %s", extractProviderErrMsg(raw))
	}
	turn := &AssistantTurn{}
	var sb strings.Builder
	fallbackPrefix := uuid.NewString()[:8]
	for i, blk := range resp.Content {
		switch blk.Type {
		case "text":
			sb.WriteString(blk.Text)
		case "tool_use":
			id := blk.ID
			if id == "" {
				id = fmt.Sprintf("toolu_%s_%d", fallbackPrefix, i+1)
			}
			args := strings.TrimSpace(string(blk.Input))
			if args == "" {
				args = "{}"
			}
			turn.ToolCalls = append(turn.ToolCalls, LLMToolCall{
				ID:        id,
				Name:      blk.Name,
				Arguments: args,
			})
		}
	}
	turn.Content = sb.String()
	if turn.Content != "" && onDelta != nil {
		onDelta(turn.Content)
	}
	return turn, nil
}

func extractProviderErrMsg(raw []byte) string {
	var parsed struct {
		Error any `json:"error"`
	}
	if json.Unmarshal(raw, &parsed) == nil && parsed.Error != nil {
		switch v := parsed.Error.(type) {
		case string:
			return v
		case map[string]any:
			if msg, ok := v["message"].(string); ok && msg != "" {
				return msg
			}
		}
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 360 {
		s = TruncateUTF8Bytes(s, 360) + "..."
	}
	if s == "" {
		return "未知错误"
	}
	return s
}
