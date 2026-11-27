package aiops

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// --- Protocol 3: Anthropic Messages Native / Compatible Streaming (/messages) ---

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
			// Preserve thinking / redacted_thinking blocks + signatures before text & tool_use
			// (strictly required by Anthropic extended/adaptive thinking multi-turn tool calling).
			if m.ProviderState != nil && m.ProviderState.Protocol == vault.AIProtocolAnthropic {
				for _, tb := range m.ProviderState.AnthropicThinking {
					switch tb.Type {
					case "thinking":
						if tb.Signature != "" {
							blocks = append(blocks, map[string]any{
								"type":      "thinking",
								"thinking":  tb.Thinking,
								"signature": tb.Signature,
							})
						}
					case "redacted_thinking":
						if tb.Data != "" {
							blocks = append(blocks, map[string]any{
								"type": "redacted_thinking",
								"data": tb.Data,
							})
						}
					}
				}
			}
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
	spec ModelSpec,
	systemPrompt string,
	history []vault.AIChatMessage,
	tools []ToolDefinition,
	cb StreamCallbacks,
) (*AssistantTurn, error) {
	anthMessages := buildAnthropicMessages(history)

	// Anthropic Messages API mandates max_tokens. If user left it unset (0), derive from catalog default.
	maxTok := prov.EffectiveMaxOutputTokens()
	autoMaxTok := false
	if maxTok <= 0 {
		autoMaxTok = true
		if spec.MaxOutputTokens > 0 {
			maxTok = spec.MaxOutputTokens
		} else {
			maxTok = 16384
		}
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

	// Reasoning / Thinking configuration (Adaptive Thinking for Claude 4.6+/5.x vs budget_tokens for 3.7/4/4.5)
	thinkingEnabled := false
	effort := vault.NormalizeAIReasoningEffort(prov.ReasoningEffort)
	if effort != vault.AIReasoningDefault {
		if effort == vault.AIReasoningOff {
			payload["thinking"] = map[string]any{"type": "disabled"}
		} else if spec.UseAdaptiveThinking {
			thinkingEnabled = true
			payload["thinking"] = map[string]any{"type": "adaptive"}
			payload["output_config"] = map[string]any{"effort": string(effort)}
		} else {
			thinkingEnabled = true
			budget := 8192
			switch effort {
			case vault.AIReasoningLow:
				budget = 2048
			case vault.AIReasoningMedium:
				budget = 8192
			case vault.AIReasoningHigh:
				budget = 16384
			case vault.AIReasoningMax:
				budget = 32768
			}
			if maxTok <= budget {
				if autoMaxTok {
					maxTok = budget + 4096
					payload["max_tokens"] = maxTok
				} else if maxTok > 1024 {
					budget = maxTok - 1024
				} else {
					budget = max(1024, maxTok/2)
				}
			}
			payload["thinking"] = map[string]any{
				"type":          "enabled",
				"budget_tokens": budget,
			}
		}
	}

	// Anthropic forbids custom temperature/top_p when thinking is enabled or on models where temperature is locked.
	// Also Anthropic 4.x+ disallows sending both temperature and top_p together; prefer temperature if both set.
	if spec.SupportsTemperature && !thinkingEnabled {
		if prov.Temperature != nil {
			payload["temperature"] = *prov.Temperature
		} else if prov.TopP != nil {
			payload["top_p"] = *prov.TopP
		}
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

	if err := mergeExtraBodyJSON(payload, prov.ExtraBodyJSON); err != nil {
		return nil, err
	}
	payload["stream"] = true

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	headers := map[string]string{
		"Content-Type":      "application/json",
		"Accept":            "text/event-stream",
		"anthropic-version": "2023-06-01",
	}
	endpoint := resolveChatEndpoint(prov, vault.AIProtocolAnthropic)
	endpoint = applyAuthAndHeaders(prov, vault.AIProtocolAnthropic, endpoint, headers)

	type anthBlock struct {
		kind      string
		id        string
		name      string
		data      string
		thinking  strings.Builder
		signature strings.Builder
		json      strings.Builder
	}
	var contentBuf strings.Builder
	var reasoningBuf strings.Builder
	blocks := make(map[int]*anthBlock)
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
		var ev struct {
			Type    string `json:"type"`
			Index   int    `json:"index"`
			Error   any    `json:"error"`
			Message *struct {
				Usage *struct {
					InputTokens              int `json:"input_tokens"`
					OutputTokens             int `json:"output_tokens"`
					CacheReadInputTokens     int `json:"cache_read_input_tokens"`
					CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
				} `json:"usage"`
			} `json:"message"`
			Usage *struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
			ContentBlock struct {
				Type      string          `json:"type"`
				ID        string          `json:"id"`
				Name      string          `json:"name"`
				Text      string          `json:"text"`
				Thinking  string          `json:"thinking"`
				Signature string          `json:"signature"`
				Data      string          `json:"data"`
				Input     json.RawMessage `json:"input"`
			} `json:"content_block"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				Thinking    string `json:"thinking"`
				Signature   string `json:"signature"`
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
		case "message_start":
			if ev.Message != nil && ev.Message.Usage != nil {
				u := ev.Message.Usage
				usage.InputTokens = u.InputTokens + u.CacheCreationInputTokens + u.CacheReadInputTokens
				usage.CachedInputTokens = u.CacheReadInputTokens
				if u.OutputTokens > 0 {
					usage.OutputTokens = u.OutputTokens
				}
			}
		case "message_delta":
			if ev.Usage != nil {
				if ev.Usage.InputTokens > 0 && usage.InputTokens == 0 {
					usage.InputTokens = ev.Usage.InputTokens
				}
				if ev.Usage.OutputTokens > 0 {
					usage.OutputTokens = ev.Usage.OutputTokens
				}
			}
		case "content_block_start":
			b := &anthBlock{
				kind: ev.ContentBlock.Type,
				id:   ev.ContentBlock.ID,
				name: ev.ContentBlock.Name,
				data: ev.ContentBlock.Data,
			}
			if ev.ContentBlock.Type == "text" && ev.ContentBlock.Text != "" {
				contentBuf.WriteString(ev.ContentBlock.Text)
				if cb.OnTextDelta != nil {
					cb.OnTextDelta(ev.ContentBlock.Text)
				}
			}
			if ev.ContentBlock.Type == "thinking" {
				if ev.ContentBlock.Thinking != "" {
					b.thinking.WriteString(ev.ContentBlock.Thinking)
					reasoningBuf.WriteString(ev.ContentBlock.Thinking)
					if cb.OnReasoningDelta != nil {
						cb.OnReasoningDelta(ev.ContentBlock.Thinking)
					}
				}
				if ev.ContentBlock.Signature != "" {
					b.signature.WriteString(ev.ContentBlock.Signature)
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
			switch ev.Delta.Type {
			case "text_delta":
				if ev.Delta.Text != "" {
					contentBuf.WriteString(ev.Delta.Text)
					if cb.OnTextDelta != nil {
						cb.OnTextDelta(ev.Delta.Text)
					}
				}
			case "thinking_delta":
				if ev.Delta.Thinking != "" {
					if b, ok := blocks[ev.Index]; ok {
						b.thinking.WriteString(ev.Delta.Thinking)
					}
					reasoningBuf.WriteString(ev.Delta.Thinking)
					if cb.OnReasoningDelta != nil {
						cb.OnReasoningDelta(ev.Delta.Thinking)
					}
				}
			case "signature_delta":
				if ev.Delta.Signature != "" {
					if b, ok := blocks[ev.Index]; ok {
						b.signature.WriteString(ev.Delta.Signature)
					}
				}
			case "input_json_delta":
				if ev.Delta.PartialJSON != "" {
					if b, ok := blocks[ev.Index]; ok {
						b.json.WriteString(ev.Delta.PartialJSON)
					}
				}
			}
		case "message_stop":
			return false
		}
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("请求 Anthropic 流式接口失败: %w", sanitizeURLError(err, prov.APIKey))
	}
	if err := validateStrictStreamMeta(meta, "Anthropic"); err != nil {
		return nil, err
	}
	if streamErrMsg != "" {
		return nil, fmt.Errorf("Anthropic 流式接口返回错误: %s", streamErrMsg)
	}

	turn := &AssistantTurn{
		Content:          contentBuf.String(),
		ReasoningContent: reasoningBuf.String(),
		Usage:            finalizeUsage(&usage),
	}

	var thinkingBlocks []vault.AIAnthropicThinkingBlock
	fallbackPrefix := uuid.NewString()[:8]
	for i := 0; i <= maxIdx; i++ {
		b, ok := blocks[i]
		if !ok {
			continue
		}
		switch b.kind {
		case "thinking":
			if b.signature.Len() > 0 || b.thinking.Len() > 0 {
				thinkingBlocks = append(thinkingBlocks, vault.AIAnthropicThinkingBlock{
					Type:      "thinking",
					Thinking:  b.thinking.String(),
					Signature: b.signature.String(),
				})
			}
		case "redacted_thinking":
			if b.data != "" {
				thinkingBlocks = append(thinkingBlocks, vault.AIAnthropicThinkingBlock{
					Type: "redacted_thinking",
					Data: b.data,
				})
			}
		case "tool_use":
			if b.name != "" {
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
	}
	if len(thinkingBlocks) > 0 {
		turn.ProviderState = &vault.AIMessageMeta{
			Protocol:          vault.AIProtocolAnthropic,
			AnthropicThinking: thinkingBlocks,
		}
	}
	return turn, nil
}

// --- Protocol 4: Google Gemini Native / Compatible Streaming (:streamGenerateContent?alt=sse) ---

func sanitizeGeminiSchema(schema map[string]any) map[string]any {
	if schema == nil {
		return nil
	}
	out := make(map[string]any, len(schema))
	for k, v := range schema {
		switch k {
		case "$schema", "additionalProperties", "default", "$defs", "definitions", "title", "examples":
			continue
		}
		switch typed := v.(type) {
		case map[string]any:
			if k == "properties" {
				props := make(map[string]any, len(typed))
				for pk, pv := range typed {
					if pMap, ok := pv.(map[string]any); ok {
						props[pk] = sanitizeGeminiSchema(pMap)
					} else {
						props[pk] = pv
					}
				}
				out[k] = props
			} else {
				out[k] = sanitizeGeminiSchema(typed)
			}
		default:
			out[k] = v
		}
	}
	return out
}

func buildGeminiContents(history []vault.AIChatMessage) []map[string]any {
	// Index toolCallID -> toolName & optional Gemini-issued functionCall ID across history
	toolNameByID := make(map[string]string)
	geminiOrigIDByCallID := make(map[string]string)
	for _, m := range history {
		if m.Role == "assistant" {
			for _, tc := range m.ToolCalls {
				if tc.ID != "" && tc.Name != "" {
					toolNameByID[tc.ID] = tc.Name
				}
				if m.ProviderState != nil && m.ProviderState.GeminiToolIDs != nil {
					if origID, ok := m.ProviderState.GeminiToolIDs[tc.ID]; ok && origID != "" {
						geminiOrigIDByCallID[tc.ID] = origID
					}
				}
			}
		}
	}

	var contents []map[string]any
	appendContent := func(role string, parts []map[string]any) {
		if len(parts) == 0 {
			return
		}
		if len(contents) > 0 && contents[len(contents)-1]["role"] == role {
			prevParts, _ := contents[len(contents)-1]["parts"].([]map[string]any)
			contents[len(contents)-1]["parts"] = append(prevParts, parts...)
			return
		}
		contents = append(contents, map[string]any{
			"role":  role,
			"parts": parts,
		})
	}

	for i := 0; i < len(history); i++ {
		m := history[i]
		switch m.Role {
		case "user":
			if strings.TrimSpace(m.Content) == "" {
				continue
			}
			appendContent("user", []map[string]any{{"text": m.Content}})

		case "assistant":
			var parts []map[string]any
			var thoughtSig string
			var toolSigs map[string]string
			var toolOrigIDs map[string]string
			if m.ProviderState != nil && m.ProviderState.Protocol == vault.AIProtocolGemini {
				thoughtSig = m.ProviderState.GeminiThoughtSignature
				toolSigs = m.ProviderState.GeminiToolSignatures
				toolOrigIDs = m.ProviderState.GeminiToolIDs
			}
			if strings.TrimSpace(m.Content) != "" {
				p := map[string]any{"text": m.Content}
				if len(m.ToolCalls) == 0 && thoughtSig != "" {
					p["thoughtSignature"] = thoughtSig
				}
				parts = append(parts, p)
			}
			for tcIdx, tc := range m.ToolCalls {
				var parsedArgs map[string]any
				if strings.TrimSpace(tc.Arguments) != "" {
					_ = json.Unmarshal([]byte(tc.Arguments), &parsedArgs)
				}
				if parsedArgs == nil {
					parsedArgs = map[string]any{}
				}
				fcObj := map[string]any{
					"name": tc.Name,
					"args": parsedArgs,
				}
				if toolOrigIDs != nil {
					if origID := toolOrigIDs[tc.ID]; origID != "" {
						fcObj["id"] = origID
					}
				}
				part := map[string]any{
					"functionCall": fcObj,
				}
				// Echo exact thoughtSignature on functionCall part (mandatory on Gemini 3/4 multi-turn tool calls!)
				if sig := toolSigs[tc.ID]; sig != "" {
					part["thoughtSignature"] = sig
				} else if tcIdx == 0 && thoughtSig != "" {
					part["thoughtSignature"] = thoughtSig
				}
				parts = append(parts, part)
			}
			appendContent("model", parts)

		case "tool":
			var respParts []map[string]any
			for ; i < len(history) && history[i].Role == "tool"; i++ {
				tm := history[i]
				fnName := strings.TrimSpace(tm.ToolName)
				if fnName == "" {
					fnName = toolNameByID[tm.ToolCallID]
				}
				if fnName == "" {
					fnName = "tool_result"
				}
				frObj := map[string]any{
					"name": fnName,
					"response": map[string]any{
						"output":   tm.Content,
						"is_error": tm.IsError,
					},
				}
				if origID := geminiOrigIDByCallID[tm.ToolCallID]; origID != "" {
					frObj["id"] = origID
				}
				respParts = append(respParts, map[string]any{
					"functionResponse": frObj,
				})
			}
			i--
			appendContent("user", respParts)
		}
	}

	// Ensure conversation starts with user turn
	for len(contents) > 0 && contents[0]["role"] != "user" {
		contents = contents[1:]
	}
	return contents
}

func mapGeminiThinkingLevel(effort vault.AIReasoningEffort, modelID string) string {
	m := canonicalModelKey(modelID)
	switch vault.NormalizeAIReasoningEffort(effort) {
	case vault.AIReasoningOff:
		return "minimal"
	case vault.AIReasoningLow:
		return "low"
	case vault.AIReasoningMedium:
		return "medium"
	case vault.AIReasoningHigh:
		return "high"
	case vault.AIReasoningMax:
		if strings.Contains(m, "gemini-4") {
			return "xhigh"
		}
		return "high"
	default:
		return ""
	}
}

func (c *LLMClient) streamGemini(
	ctx context.Context,
	prov vault.AIProviderConfig,
	spec ModelSpec,
	systemPrompt string,
	history []vault.AIChatMessage,
	tools []ToolDefinition,
	cb StreamCallbacks,
) (*AssistantTurn, error) {
	payload := map[string]any{
		"contents": buildGeminiContents(history),
	}
	if strings.TrimSpace(systemPrompt) != "" {
		payload["systemInstruction"] = map[string]any{
			"parts": []map[string]any{{"text": systemPrompt}},
		}
	}

	genCfg := map[string]any{}
	if maxOut := prov.EffectiveMaxOutputTokens(); maxOut > 0 {
		genCfg["maxOutputTokens"] = maxOut
	}
	if prov.Temperature != nil {
		genCfg["temperature"] = *prov.Temperature
	}
	if prov.TopP != nil {
		genCfg["topP"] = *prov.TopP
	}

	// Gemini ThinkingConfig (thinkingLevel for Gemini 3/4/latest vs thinkingBudget for Gemini 2.5)
	effort := vault.NormalizeAIReasoningEffort(prov.ReasoningEffort)
	if effort != vault.AIReasoningDefault {
		tc := map[string]any{}
		if spec.GeminiUseThinkingLevel {
			if lvl := mapGeminiThinkingLevel(effort, prov.Model); lvl != "" {
				tc["thinkingLevel"] = lvl
			}
			if effort != vault.AIReasoningOff {
				tc["includeThoughts"] = true
			}
		} else {
			switch effort {
			case vault.AIReasoningOff:
				tc["thinkingBudget"] = 0
			case vault.AIReasoningLow:
				tc["thinkingBudget"] = 1024
				tc["includeThoughts"] = true
			case vault.AIReasoningMedium:
				tc["thinkingBudget"] = 8192
				tc["includeThoughts"] = true
			case vault.AIReasoningHigh:
				tc["thinkingBudget"] = 16384
				tc["includeThoughts"] = true
			case vault.AIReasoningMax:
				tc["thinkingBudget"] = 24576
				tc["includeThoughts"] = true
			}
		}
		if len(tc) > 0 {
			genCfg["thinkingConfig"] = tc
		}
	} else if spec.SupportsReasoning && cb.OnReasoningDelta != nil {
		// When streaming to interactive UI with reasoning-capable Gemini models, request thought summaries gently
		genCfg["thinkingConfig"] = map[string]any{"includeThoughts": true}
	}

	if len(genCfg) > 0 {
		payload["generationConfig"] = genCfg
	}

	if len(tools) > 0 {
		decls := make([]map[string]any, len(tools))
		for i, td := range tools {
			decls[i] = map[string]any{
				"name":        td.Name,
				"description": td.Description,
				"parameters":  sanitizeGeminiSchema(td.Parameters),
			}
		}
		payload["tools"] = []map[string]any{
			{"functionDeclarations": decls},
		}
	}

	if err := mergeExtraBodyJSON(payload, prov.ExtraBodyJSON); err != nil {
		return nil, err
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "text/event-stream",
	}
	endpoint := resolveChatEndpoint(prov, vault.AIProtocolGemini)
	endpoint = applyAuthAndHeaders(prov, vault.AIProtocolGemini, endpoint, headers)

	var contentBuf strings.Builder
	var reasoningBuf strings.Builder
	var toolCalls []LLMToolCall
	toolSigs := make(map[string]string)
	toolOrigIDs := make(map[string]string)
	var lastThoughtSig string
	var streamErrMsg string
	var usage vault.AITokenUsage
	fallbackPrefix := uuid.NewString()[:8]

	meta, err := c.Transport().PostStream(ctx, endpoint, headers, bodyBytes, func(rawLine string) bool {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "data:") {
			return true
		}
		dataStr := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if dataStr == "" || dataStr == "[DONE]" {
			return dataStr != "[DONE]"
		}

		var chunk struct {
			Error      any `json:"error"`
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text             string `json:"text"`
						Thought          bool   `json:"thought"`
						ThoughtSignature string `json:"thoughtSignature"`
						FunctionCall     *struct {
							ID   string         `json:"id"`
							Name string         `json:"name"`
							Args map[string]any `json:"args"`
						} `json:"functionCall"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
			UsageMetadata *struct {
				PromptTokenCount        int `json:"promptTokenCount"`
				CandidatesTokenCount    int `json:"candidatesTokenCount"`
				ThoughtsTokenCount      int `json:"thoughtsTokenCount"`
				CachedContentTokenCount int `json:"cachedContentTokenCount"`
				TotalTokenCount         int `json:"totalTokenCount"`
			} `json:"usageMetadata"`
		}
		if json.Unmarshal([]byte(dataStr), &chunk) != nil {
			return true
		}
		if chunk.Error != nil {
			streamErrMsg = extractProviderErrMsg([]byte(dataStr))
			return false
		}
		if chunk.UsageMetadata != nil {
			um := chunk.UsageMetadata
			if um.PromptTokenCount > 0 {
				usage.InputTokens = um.PromptTokenCount
			}
			if um.CandidatesTokenCount > 0 || um.ThoughtsTokenCount > 0 {
				usage.OutputTokens = um.CandidatesTokenCount + um.ThoughtsTokenCount
			}
			if um.ThoughtsTokenCount > 0 {
				usage.ReasoningTokens = um.ThoughtsTokenCount
			}
			if um.CachedContentTokenCount > 0 {
				usage.CachedInputTokens = um.CachedContentTokenCount
			}
			if um.TotalTokenCount > 0 {
				usage.TotalTokens = um.TotalTokenCount
			}
		}

		for _, cand := range chunk.Candidates {
			for _, part := range cand.Content.Parts {
				if part.ThoughtSignature != "" {
					lastThoughtSig = part.ThoughtSignature
				}
				if part.Thought {
					if part.Text != "" {
						reasoningBuf.WriteString(part.Text)
						if cb.OnReasoningDelta != nil {
							cb.OnReasoningDelta(part.Text)
						}
					}
					continue
				}
				if part.Text != "" {
					contentBuf.WriteString(part.Text)
					if cb.OnTextDelta != nil {
						cb.OnTextDelta(part.Text)
					}
				}
				if part.FunctionCall != nil && part.FunctionCall.Name != "" {
					callID := strings.TrimSpace(part.FunctionCall.ID)
					origID := callID
					if callID == "" {
						callID = fmt.Sprintf("gem_%s_%d", fallbackPrefix, len(toolCalls)+1)
					}
					argsBytes := []byte("{}")
					if part.FunctionCall.Args != nil {
						if b, mErr := json.Marshal(part.FunctionCall.Args); mErr == nil {
							argsBytes = b
						}
					}
					toolCalls = append(toolCalls, LLMToolCall{
						ID:        callID,
						Name:      part.FunctionCall.Name,
						Arguments: string(argsBytes),
					})
					if part.ThoughtSignature != "" {
						toolSigs[callID] = part.ThoughtSignature
					}
					if origID != "" {
						toolOrigIDs[callID] = origID
					}
				}
			}
		}
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("请求 Gemini 流式接口失败: %w", sanitizeURLError(err, prov.APIKey))
	}
	if err := validateStrictStreamMeta(meta, "Gemini"); err != nil {
		return nil, err
	}
	if streamErrMsg != "" {
		return nil, fmt.Errorf("Gemini 流式接口返回错误: %s", streamErrMsg)
	}

	turn := &AssistantTurn{
		Content:          contentBuf.String(),
		ReasoningContent: reasoningBuf.String(),
		ToolCalls:        toolCalls,
		Usage:            finalizeUsage(&usage),
	}
	if lastThoughtSig != "" || len(toolSigs) > 0 || len(toolOrigIDs) > 0 {
		ps := &vault.AIMessageMeta{
			Protocol:               vault.AIProtocolGemini,
			GeminiThoughtSignature: lastThoughtSig,
		}
		if len(toolSigs) > 0 {
			ps.GeminiToolSignatures = toolSigs
		}
		if len(toolOrigIDs) > 0 {
			ps.GeminiToolIDs = toolOrigIDs
		}
		turn.ProviderState = ps
	}
	return turn, nil
}
