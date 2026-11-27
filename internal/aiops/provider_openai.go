package aiops

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// --- Protocol 1: OpenAI Chat Completions Compatible Streaming (/chat/completions) ---

func mapOpenAIReasoningEffort(effort vault.AIReasoningEffort, modelID string) string {
	m := canonicalModelKey(modelID)
	switch vault.NormalizeAIReasoningEffort(effort) {
	case vault.AIReasoningOff:
		return "none"
	case vault.AIReasoningLow:
		return "low"
	case vault.AIReasoningMedium:
		return "medium"
	case vault.AIReasoningHigh:
		return "high"
	case vault.AIReasoningMax:
		// GPT-5.2+ / GPT-6.x / Qwen4 support xhigh; older o-series / GPT-5 cap at high
		if strings.HasPrefix(m, "gpt-6") || strings.HasPrefix(m, "gpt-5.2") || strings.HasPrefix(m, "gpt-5.3") ||
			strings.HasPrefix(m, "gpt-5.4") || strings.HasPrefix(m, "gpt-5.5") || strings.HasPrefix(m, "gpt-5.6") ||
			strings.HasPrefix(m, "qwen4") {
			return "xhigh"
		}
		return "high"
	default:
		return ""
	}
}

func buildOpenAIChatMessages(systemPrompt string, history []vault.AIChatMessage, spec ModelSpec) []map[string]any {
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
			// Preserve interleaved reasoning_content across multi-turn tool calls (required by DeepSeek V3.2/V4, Kimi K2.5/K3, GLM-5, Qwen3.5+/4)
			if len(m.ToolCalls) > 0 && strings.TrimSpace(m.ReasoningContent) != "" && spec.InterleavedReasoningKey != "" {
				item[spec.InterleavedReasoningKey] = m.ReasoningContent
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
	return messages
}

func (c *LLMClient) streamOpenAIChat(
	ctx context.Context,
	prov vault.AIProviderConfig,
	spec ModelSpec,
	systemPrompt string,
	history []vault.AIChatMessage,
	tools []ToolDefinition,
	cb StreamCallbacks,
) (*AssistantTurn, error) {
	messages := buildOpenAIChatMessages(systemPrompt, history, spec)

	useMaxCompletionTokens := spec.UseMaxCompletionTokens
	includeStreamOptions := true

	for attempt := 0; attempt < 2; attempt++ {
		payload := map[string]any{
			"model":    prov.Model,
			"messages": messages,
			"stream":   true,
		}
		if includeStreamOptions {
			payload["stream_options"] = map[string]any{"include_usage": true}
		}

		// Omit max output limit when unset (0) so upstream applies full model default.
		if maxOut := prov.EffectiveMaxOutputTokens(); maxOut > 0 {
			if useMaxCompletionTokens {
				payload["max_completion_tokens"] = maxOut
			} else {
				payload["max_tokens"] = maxOut
			}
		}

		// Sampling parameters (automatically omit temperature/top_p on reasoning models that forbid them)
		if spec.SupportsTemperature {
			if prov.Temperature != nil {
				payload["temperature"] = *prov.Temperature
			}
			if prov.TopP != nil {
				payload["top_p"] = *prov.TopP
			}
		}

		// Reasoning effort adaptation
		if effort := vault.NormalizeAIReasoningEffort(prov.ReasoningEffort); effort != vault.AIReasoningDefault {
			lowerBase := strings.ToLower(prov.BaseURL)
			lowerModel := canonicalModelKey(prov.Model)
			switch {
			case strings.Contains(lowerBase, "deepseek.com") && effort == vault.AIReasoningOff && !strings.Contains(lowerModel, "reasoner"):
				payload["thinking"] = map[string]any{"type": "disabled"}
			case strings.Contains(lowerBase, "dashscope") && strings.Contains(lowerModel, "qwen"):
				if effort == vault.AIReasoningOff {
					payload["enable_thinking"] = false
				} else {
					payload["enable_thinking"] = true
					payload["reasoning_effort"] = mapOpenAIReasoningEffort(effort, prov.Model)
				}
			default:
				if mapped := mapOpenAIReasoningEffort(effort, prov.Model); mapped != "" {
					payload["reasoning_effort"] = mapped
				}
			}
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

		if err := mergeExtraBodyJSON(payload, prov.ExtraBodyJSON); err != nil {
			return nil, err
		}
		// Strictly enforce streaming mode even if ExtraBodyJSON accidentally had stream:false.
		payload["stream"] = true

		bodyBytes, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}

		headers := map[string]string{
			"Content-Type": "application/json",
			"Accept":       "text/event-stream",
		}
		endpoint := resolveChatEndpoint(prov, vault.AIProtocolOpenAI)
		endpoint = applyAuthAndHeaders(prov, vault.AIProtocolOpenAI, endpoint, headers)

		turn, meta, err := c.execOpenAIChatStream(ctx, endpoint, headers, bodyBytes, prov.APIKey, cb)
		if err == nil {
			return turn, nil
		}

		// Automatic parameter resilience on first attempt for third-party relays that reject stream_options or max_tokens/max_completion_tokens
		if attempt == 0 && meta != nil && meta.StatusCode == 400 {
			errLower := strings.ToLower(string(meta.RawBody))
			retry := false
			if includeStreamOptions && strings.Contains(errLower, "stream_options") {
				includeStreamOptions = false
				retry = true
			}
			if useMaxCompletionTokens && strings.Contains(errLower, "max_completion_tokens") {
				useMaxCompletionTokens = false
				retry = true
			} else if !useMaxCompletionTokens && strings.Contains(errLower, "max_tokens") && strings.Contains(errLower, "max_completion_tokens") {
				useMaxCompletionTokens = true
				retry = true
			}
			if retry {
				continue
			}
		}
		return nil, err
	}

	return nil, fmt.Errorf("请求 OpenAI 兼容流式接口失败")
}

func (c *LLMClient) execOpenAIChatStream(
	ctx context.Context,
	endpoint string,
	headers map[string]string,
	bodyBytes []byte,
	apiKey string,
	cb StreamCallbacks,
) (*AssistantTurn, *StreamResponseMeta, error) {
	type partialCall struct {
		id   string
		name string
		args strings.Builder
	}
	var contentBuf strings.Builder
	var reasoningBuf strings.Builder
	callByIdx := make(map[int]*partialCall)
	maxIdx := -1
	var streamErrMsg string
	var usage vault.AITokenUsage

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
			Error any `json:"error"`
			Usage *struct {
				PromptTokens        int `json:"prompt_tokens"`
				CompletionTokens    int `json:"completion_tokens"`
				TotalTokens         int `json:"total_tokens"`
				PromptTokensDetails *struct {
					CachedTokens int `json:"cached_tokens"`
				} `json:"prompt_tokens_details"`
				CompletionTokensDetails *struct {
					ReasoningTokens int `json:"reasoning_tokens"`
				} `json:"completion_tokens_details"`
			} `json:"usage"`
			Choices []struct {
				Delta struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
					Reasoning        string `json:"reasoning"`
					ToolCalls        []struct {
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
		if chunk.Usage != nil {
			if chunk.Usage.PromptTokens > 0 {
				usage.InputTokens = chunk.Usage.PromptTokens
			}
			if chunk.Usage.CompletionTokens > 0 {
				usage.OutputTokens = chunk.Usage.CompletionTokens
			}
			if chunk.Usage.TotalTokens > 0 {
				usage.TotalTokens = chunk.Usage.TotalTokens
			}
			if chunk.Usage.PromptTokensDetails != nil && chunk.Usage.PromptTokensDetails.CachedTokens > 0 {
				usage.CachedInputTokens = chunk.Usage.PromptTokensDetails.CachedTokens
			}
			if chunk.Usage.CompletionTokensDetails != nil && chunk.Usage.CompletionTokensDetails.ReasoningTokens > 0 {
				usage.ReasoningTokens = chunk.Usage.CompletionTokensDetails.ReasoningTokens
			}
		}
		for _, ch := range chunk.Choices {
			rDelta := ch.Delta.ReasoningContent
			if rDelta == "" {
				rDelta = ch.Delta.Reasoning
			}
			if rDelta != "" {
				reasoningBuf.WriteString(rDelta)
				if cb.OnReasoningDelta != nil {
					cb.OnReasoningDelta(rDelta)
				}
			}
			if ch.Delta.Content != "" {
				contentBuf.WriteString(ch.Delta.Content)
				if cb.OnTextDelta != nil {
					cb.OnTextDelta(ch.Delta.Content)
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
		return nil, meta, fmt.Errorf("请求大模型流式接口失败: %w", sanitizeURLError(err, apiKey))
	}
	if err := validateStrictStreamMeta(meta, "OpenAI 兼容"); err != nil {
		return nil, meta, err
	}
	if streamErrMsg != "" {
		return nil, meta, fmt.Errorf("模型流式接口返回错误: %s", streamErrMsg)
	}

	turn := &AssistantTurn{
		Content:          contentBuf.String(),
		ReasoningContent: reasoningBuf.String(),
		Usage:            finalizeUsage(&usage),
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
	return turn, meta, nil
}

// --- Protocol 2: OpenAI Responses API Streaming (/responses) ---

func buildOpenAIResponsesInput(history []vault.AIChatMessage) []any {
	input := make([]any, 0, len(history))
	for _, m := range history {
		switch m.Role {
		case "user":
			input = append(input, map[string]any{
				"type": "message",
				"role": "user",
				"content": []map[string]any{
					{"type": "input_text", "text": m.Content},
				},
			})
		case "assistant":
			// Echo preserved opaque reasoning items from Responses API before tool calls / message
			if m.ProviderState != nil && m.ProviderState.Protocol == vault.AIProtocolOpenAIResponses {
				for _, rawItem := range m.ProviderState.ResponsesReasoningRaw {
					var parsed any
					if json.Unmarshal([]byte(rawItem), &parsed) == nil && parsed != nil {
						input = append(input, parsed)
					}
				}
			}
			if strings.TrimSpace(m.Content) != "" {
				input = append(input, map[string]any{
					"type": "message",
					"role": "assistant",
					"content": []map[string]any{
						{"type": "output_text", "text": m.Content},
					},
				})
			}
			for _, tc := range m.ToolCalls {
				args := strings.TrimSpace(tc.Arguments)
				if args == "" {
					args = "{}"
				}
				input = append(input, map[string]any{
					"type":      "function_call",
					"call_id":   tc.ID,
					"name":      tc.Name,
					"arguments": args,
				})
			}
		case "tool":
			input = append(input, map[string]any{
				"type":    "function_call_output",
				"call_id": m.ToolCallID,
				"output":  m.Content,
			})
		}
	}
	return input
}

func (c *LLMClient) streamOpenAIResponses(
	ctx context.Context,
	prov vault.AIProviderConfig,
	spec ModelSpec,
	systemPrompt string,
	history []vault.AIChatMessage,
	tools []ToolDefinition,
	cb StreamCallbacks,
) (*AssistantTurn, error) {
	payload := map[string]any{
		"model":  prov.Model,
		"input":  buildOpenAIResponsesInput(history),
		"stream": true,
	}
	if strings.TrimSpace(systemPrompt) != "" {
		payload["instructions"] = systemPrompt
	}
	if maxOut := prov.EffectiveMaxOutputTokens(); maxOut > 0 {
		payload["max_output_tokens"] = maxOut
	}
	if spec.SupportsTemperature {
		if prov.Temperature != nil {
			payload["temperature"] = *prov.Temperature
		}
		if prov.TopP != nil {
			payload["top_p"] = *prov.TopP
		}
	}
	if effort := vault.NormalizeAIReasoningEffort(prov.ReasoningEffort); effort != vault.AIReasoningDefault {
		if mapped := mapOpenAIReasoningEffort(effort, prov.Model); mapped != "" {
			rObj := map[string]any{"effort": mapped}
			if mapped != "none" {
				rObj["summary"] = "auto"
			}
			payload["reasoning"] = rObj
		}
	}
	if len(tools) > 0 {
		respTools := make([]map[string]any, len(tools))
		for i, td := range tools {
			respTools[i] = map[string]any{
				"type":        "function",
				"name":        td.Name,
				"description": td.Description,
				"parameters":  td.Parameters,
			}
		}
		payload["tools"] = respTools
	}

	if err := mergeExtraBodyJSON(payload, prov.ExtraBodyJSON); err != nil {
		return nil, err
	}
	payload["stream"] = true

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "text/event-stream",
	}
	endpoint := resolveChatEndpoint(prov, vault.AIProtocolOpenAIResponses)
	endpoint = applyAuthAndHeaders(prov, vault.AIProtocolOpenAIResponses, endpoint, headers)

	type respFuncCall struct {
		callID string
		itemID string
		name   string
		args   strings.Builder
		final  string
	}

	var contentBuf strings.Builder
	var reasoningBuf strings.Builder
	callsByIdx := make(map[int]*respFuncCall)
	idxByItemID := make(map[string]int)
	maxOutIdx := -1
	var reasoningItemsRaw []string
	var streamErrMsg string
	var usage vault.AITokenUsage

	getOrCreateCall := func(outIdx int, itemID string) *respFuncCall {
		if itemID != "" {
			if mapped, ok := idxByItemID[itemID]; ok {
				outIdx = mapped
			}
		}
		if outIdx < 0 {
			outIdx = maxOutIdx + 1
		}
		fc, ok := callsByIdx[outIdx]
		if !ok {
			fc = &respFuncCall{itemID: itemID}
			callsByIdx[outIdx] = fc
			if outIdx > maxOutIdx {
				maxOutIdx = outIdx
			}
		}
		if itemID != "" {
			fc.itemID = itemID
			idxByItemID[itemID] = outIdx
		}
		return fc
	}

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

		var ev struct {
			Type        string          `json:"type"`
			OutputIndex int             `json:"output_index"`
			ItemID      string          `json:"item_id"`
			Delta       string          `json:"delta"`
			Arguments   string          `json:"arguments"`
			Name        string          `json:"name"`
			CallID      string          `json:"call_id"`
			Error       any             `json:"error"`
			Item        json.RawMessage `json:"item"`
			Response    *struct {
				Error any `json:"error"`
				Usage *struct {
					InputTokens        int `json:"input_tokens"`
					OutputTokens       int `json:"output_tokens"`
					TotalTokens        int `json:"total_tokens"`
					InputTokensDetails *struct {
						CachedTokens int `json:"cached_tokens"`
					} `json:"input_tokens_details"`
					OutputTokensDetails *struct {
						ReasoningTokens int `json:"reasoning_tokens"`
					} `json:"output_tokens_details"`
				} `json:"usage"`
			} `json:"response"`
		}
		if json.Unmarshal([]byte(dataStr), &ev) != nil {
			return true
		}

		switch ev.Type {
		case "error":
			streamErrMsg = extractProviderErrMsg([]byte(dataStr))
			return false

		case "response.failed":
			if ev.Response != nil && ev.Response.Error != nil {
				if msg := parseErrorValue(ev.Response.Error); msg != "" {
					streamErrMsg = msg
				}
			}
			if streamErrMsg == "" {
				streamErrMsg = extractProviderErrMsg([]byte(dataStr))
			}
			return false

		case "response.output_text.delta":
			if ev.Delta != "" {
				contentBuf.WriteString(ev.Delta)
				if cb.OnTextDelta != nil {
					cb.OnTextDelta(ev.Delta)
				}
			}

		case "response.reasoning_text.delta", "response.reasoning_summary_text.delta":
			if ev.Delta != "" {
				reasoningBuf.WriteString(ev.Delta)
				if cb.OnReasoningDelta != nil {
					cb.OnReasoningDelta(ev.Delta)
				}
			}

		case "response.output_item.added":
			var item struct {
				Type      string `json:"type"`
				ID        string `json:"id"`
				CallID    string `json:"call_id"`
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}
			if len(ev.Item) > 0 && json.Unmarshal(ev.Item, &item) == nil && item.Type == "function_call" {
				fc := getOrCreateCall(ev.OutputIndex, item.ID)
				if item.CallID != "" {
					fc.callID = item.CallID
				}
				if item.Name != "" {
					fc.name = item.Name
				}
				if item.Arguments != "" {
					fc.args.WriteString(item.Arguments)
				}
			}

		case "response.function_call_arguments.delta":
			if ev.Delta != "" {
				fc := getOrCreateCall(ev.OutputIndex, ev.ItemID)
				fc.args.WriteString(ev.Delta)
			}

		case "response.function_call_arguments.done":
			fc := getOrCreateCall(ev.OutputIndex, ev.ItemID)
			if ev.Name != "" {
				fc.name = ev.Name
			}
			if ev.CallID != "" {
				fc.callID = ev.CallID
			}
			if strings.TrimSpace(ev.Arguments) != "" {
				fc.final = ev.Arguments
			}

		case "response.output_item.done":
			var item struct {
				Type      string `json:"type"`
				ID        string `json:"id"`
				CallID    string `json:"call_id"`
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}
			if len(ev.Item) > 0 && json.Unmarshal(ev.Item, &item) == nil {
				switch item.Type {
				case "function_call":
					fc := getOrCreateCall(ev.OutputIndex, item.ID)
					if item.CallID != "" {
						fc.callID = item.CallID
					}
					if item.Name != "" {
						fc.name = item.Name
					}
					if strings.TrimSpace(item.Arguments) != "" {
						fc.final = item.Arguments
					}
				case "reasoning":
					reasoningItemsRaw = append(reasoningItemsRaw, string(ev.Item))
				}
			}

		case "response.completed", "response.incomplete":
			if ev.Response != nil && ev.Response.Usage != nil {
				u := ev.Response.Usage
				usage.InputTokens = u.InputTokens
				usage.OutputTokens = u.OutputTokens
				usage.TotalTokens = u.TotalTokens
				if u.InputTokensDetails != nil {
					usage.CachedInputTokens = u.InputTokensDetails.CachedTokens
				}
				if u.OutputTokensDetails != nil {
					usage.ReasoningTokens = u.OutputTokensDetails.ReasoningTokens
				}
			}
		}
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("请求 OpenAI Responses 流式接口失败: %w", sanitizeURLError(err, prov.APIKey))
	}
	if err := validateStrictStreamMeta(meta, "OpenAI Responses"); err != nil {
		return nil, err
	}
	if streamErrMsg != "" {
		return nil, fmt.Errorf("OpenAI Responses 流式接口返回错误: %s", streamErrMsg)
	}

	turn := &AssistantTurn{
		Content:          contentBuf.String(),
		ReasoningContent: reasoningBuf.String(),
		Usage:            finalizeUsage(&usage),
	}
	if len(reasoningItemsRaw) > 0 {
		turn.ProviderState = &vault.AIMessageMeta{
			Protocol:              vault.AIProtocolOpenAIResponses,
			ResponsesReasoningRaw: reasoningItemsRaw,
		}
	}

	fallbackPrefix := uuid.NewString()[:8]
	for i := 0; i <= maxOutIdx; i++ {
		if fc, ok := callsByIdx[i]; ok && fc.name != "" {
			id := fc.callID
			if id == "" {
				id = fc.itemID
			}
			if id == "" {
				id = fmt.Sprintf("call_%s_%d", fallbackPrefix, i+1)
			}
			args := strings.TrimSpace(fc.final)
			if args == "" {
				args = strings.TrimSpace(fc.args.String())
			}
			if args == "" {
				args = "{}"
			}
			turn.ToolCalls = append(turn.ToolCalls, LLMToolCall{
				ID:        id,
				Name:      fc.name,
				Arguments: args,
			})
		}
	}
	return turn, nil
}
