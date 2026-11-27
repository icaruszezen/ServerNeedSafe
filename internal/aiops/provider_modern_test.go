package aiops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

func intPtr(v int) *int           { return &v }
func floatPtr(v float64) *float64 { return &v }

func TestOpenAIChatAdaptationRetriesAndInterleavedReasoning(t *testing.T) {
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

	var capturedBodies []map[string]any
	var retryHits atomic.Int32

	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		capturedBodies = append(capturedBodies, body)

		switch r.URL.Path {
		case "/gpt6/v1/chat/completions":
			w.Header().Set("Content-Type", "text/event-stream")
			flusher := w.(http.Flusher)
			_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"先检查参数\"}}]}\n\n")
			_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"GPT-6 正常\"}}]}\n\n")
			_, _ = fmt.Fprint(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":120,\"completion_tokens\":45,\"total_tokens\":165,\"prompt_tokens_details\":{\"cached_tokens\":32},\"completion_tokens_details\":{\"reasoning_tokens\":20}}}\n\n")
			_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
			flusher.Flush()

		case "/relay-retry/v1/chat/completions":
			n := retryHits.Add(1)
			if n == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":{"message":"Unsupported parameter: stream_options"}}`))
				return
			}
			// Simulate proxy with mislabeled Content-Type: text/plain that STILL emits valid SSE data: lines
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			flusher := w.(http.Flusher)
			_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"重试流式成功\"}}]}\n\n")
			_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
			flusher.Flush()

		case "/non-stream/v1/chat/completions":
			// Gateway ignored stream:true and returned non-streaming JSON -> MUST be rejected
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"plain non-stream"}}]}`))

		default:
			http.NotFound(w, r)
		}
	}))
	defer mock.Close()

	client := NewLLMClient()

	// 1. GPT-6.2-sol: should use max_completion_tokens, omit temperature (locked on gpt-6.2-sol), merge ExtraBodyJSON, and keep stream=true
	var gotReason, gotText strings.Builder
	turn, err := client.StreamChat(context.Background(), vault.AIProviderConfig{
		Protocol:        vault.AIProtocolOpenAI,
		BaseURL:         mock.URL + "/gpt6/v1",
		APIKey:          "sk-test",
		Model:           "gpt-6.2-sol",
		MaxOutputTokens: 16000,
		Temperature:     floatPtr(0.5),
		ReasoningEffort: vault.AIReasoningMax,
		ExtraBodyJSON:   `{"stream": false, "service_tier": "priority"}`,
	}, "sys", []vault.AIChatMessage{{Role: "user", Content: "ping"}}, nil, StreamCallbacks{
		OnTextDelta:      func(s string) { gotText.WriteString(s) },
		OnReasoningDelta: func(s string) { gotReason.WriteString(s) },
	})
	if err != nil {
		t.Fatalf("StreamChat gpt-6.2-sol failed: %v", err)
	}
	if gotText.String() != "GPT-6 正常" || gotReason.String() != "先检查参数" {
		t.Fatalf("unexpected stream output: text=%q reason=%q", gotText.String(), gotReason.String())
	}
	if turn.Usage == nil || turn.Usage.InputTokens != 120 || turn.Usage.CachedInputTokens != 32 || turn.Usage.ReasoningTokens != 20 {
		t.Fatalf("unexpected usage: %+v", turn.Usage)
	}

	req0 := capturedBodies[0]
	if req0["stream"] != true {
		t.Fatalf("expected stream=true to be strictly enforced even when ExtraBodyJSON set stream=false, got %v", req0["stream"])
	}
	if req0["max_completion_tokens"] != float64(16000) {
		t.Fatalf("expected max_completion_tokens=16000 for gpt-6.2-sol, got %v (max_tokens=%v)", req0["max_completion_tokens"], req0["max_tokens"])
	}
	if _, hasOld := req0["max_tokens"]; hasOld {
		t.Fatalf("did not expect max_tokens on gpt-6.2-sol")
	}
	if _, hasTemp := req0["temperature"]; hasTemp {
		t.Fatalf("expected temperature to be omitted on gpt-6.2-sol (temp=false)")
	}
	if req0["reasoning_effort"] != "xhigh" {
		t.Fatalf("expected reasoning_effort=xhigh for gpt-6.2-sol max, got %v", req0["reasoning_effort"])
	}
	if req0["service_tier"] != "priority" {
		t.Fatalf("expected ExtraBodyJSON service_tier=priority merged, got %v", req0["service_tier"])
	}

	// 2. Interleaved reasoning_content round-trip on DeepSeek V4 tool call history + automatic retry without stream_options + text/plain SSE tolerance
	turn2, err := client.StreamChat(context.Background(), vault.AIProviderConfig{
		Protocol:        vault.AIProtocolOpenAI,
		BaseURL:         mock.URL + "/relay-retry/v1",
		APIKey:          "sk-ds",
		Model:           "deepseek-v4-pro",
		MaxOutputTokens: 0, // unset -> omit max_tokens
	}, "sys", []vault.AIChatMessage{
		{Role: "user", Content: "check disk"},
		{
			Role:             "assistant",
			Content:          "",
			ReasoningContent: "need df -h",
			ToolCalls:        []vault.AIToolCallRecord{{ID: "call_1", Name: "exec_ssh_command", Arguments: `{"command":"df -h"}`}},
		},
		{Role: "tool", ToolCallID: "call_1", Content: "/dev/vda1 50%"},
	}, nil, StreamCallbacks{})
	if err != nil {
		t.Fatalf("relay-retry StreamChat failed: %v", err)
	}
	if turn2.Content != "重试流式成功" || retryHits.Load() != 2 {
		t.Fatalf("expected retry success, content=%q hits=%d", turn2.Content, retryHits.Load())
	}
	dsReq := capturedBodies[len(capturedBodies)-1]
	if _, hasMax := dsReq["max_tokens"]; hasMax {
		t.Fatalf("expected max_tokens omitted when MaxOutputTokens=0")
	}
	msgs, _ := dsReq["messages"].([]any)
	foundReasoningEcho := false
	for _, m := range msgs {
		mm, _ := m.(map[string]any)
		if mm["role"] == "assistant" && mm["reasoning_content"] == "need df -h" {
			foundReasoningEcho = true
		}
	}
	if !foundReasoningEcho {
		t.Fatalf("expected reasoning_content echoed on assistant tool-call turn for deepseek-v4-pro")
	}

	// 3. Strictly reject non-streaming JSON responses
	_, err = client.StreamChat(context.Background(), vault.AIProviderConfig{
		Protocol: vault.AIProtocolOpenAI,
		BaseURL:  mock.URL + "/non-stream/v1",
		APIKey:   "sk-test",
		Model:    "gpt-4o",
	}, "sys", []vault.AIChatMessage{{Role: "user", Content: "hi"}}, nil, StreamCallbacks{})
	if err == nil || !strings.Contains(err.Error(), "非流式响应") {
		t.Fatalf("expected strict non-streaming rejection error, got err=%v", err)
	}
}

func TestOpenAIResponsesAPIStreamingAndReasoningRoundTrip(t *testing.T) {
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

	var captured []map[string]any
	var callCount atomic.Int32

	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" {
			http.NotFound(w, r)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		captured = append(captured, body)

		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		n := callCount.Add(1)
		if n == 1 {
			events := []string{
				`{"type":"response.reasoning_summary_text.delta","output_index":0,"delta":"分析负载指标..."}`,
				`{"type":"response.output_item.done","output_index":0,"item":{"id":"rs_1","type":"reasoning","encrypted_content":"enc_abc123","summary":[{"type":"summary_text","text":"分析负载指标..."}]}}`,
				`{"type":"response.output_item.added","output_index":1,"item":{"id":"fc_item_1","type":"function_call","call_id":"call_resp_1","name":"probe_server"}}`,
				`{"type":"response.function_call_arguments.delta","output_index":1,"item_id":"fc_item_1","delta":"{\"server_id\":\"srv-1\"}"}`,
				`{"type":"response.output_item.done","output_index":1,"item":{"id":"fc_item_1","type":"function_call","call_id":"call_resp_1","name":"probe_server","arguments":"{\"server_id\":\"srv-1\"}"}}`,
				`{"type":"response.completed","response":{"usage":{"input_tokens":200,"output_tokens":60,"total_tokens":260,"input_tokens_details":{"cached_tokens":50},"output_tokens_details":{"reasoning_tokens":35}}}}`,
			}
			for _, ev := range events {
				_, _ = fmt.Fprintf(w, "data: %s\n\n", ev)
				flusher.Flush()
			}
			return
		}
		_, _ = fmt.Fprintf(w, "data: %s\n\n", `{"type":"response.output_text.delta","output_index":0,"delta":"巡检完毕，一切正常。"}`)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", `{"type":"response.completed","response":{"usage":{"input_tokens":320,"output_tokens":20,"total_tokens":340}}}`)
		flusher.Flush()
	}))
	defer mock.Close()

	client := NewLLMClient()
	prov := vault.AIProviderConfig{
		Protocol:        vault.AIProtocolOpenAIResponses,
		BaseURL:         mock.URL + "/v1",
		APIKey:          "sk-resp",
		Model:           "gpt-6.2-sol",
		ReasoningEffort: vault.AIReasoningHigh,
	}

	var rBuf strings.Builder
	turn1, err := client.StreamChat(context.Background(), prov, "SRE prompt", []vault.AIChatMessage{
		{Role: "user", Content: "check srv-1"},
	}, []ToolDefinition{{Name: "probe_server", Description: "probe", Parameters: map[string]any{"type": "object"}}}, StreamCallbacks{
		OnReasoningDelta: func(s string) { rBuf.WriteString(s) },
	})
	if err != nil {
		t.Fatalf("Responses API turn1 failed: %v", err)
	}
	if rBuf.String() != "分析负载指标..." || len(turn1.ToolCalls) != 1 || turn1.ToolCalls[0].ID != "call_resp_1" {
		t.Fatalf("unexpected Responses turn1: reason=%q calls=%+v", rBuf.String(), turn1.ToolCalls)
	}
	if turn1.ProviderState == nil || len(turn1.ProviderState.ResponsesReasoningRaw) != 1 {
		t.Fatalf("expected raw reasoning item preserved, got %+v", turn1.ProviderState)
	}
	if turn1.Usage == nil || turn1.Usage.CachedInputTokens != 50 || turn1.Usage.ReasoningTokens != 35 {
		t.Fatalf("unexpected Responses usage: %+v", turn1.Usage)
	}

	// Turn 2: ensure preserved reasoning item + function_call + function_call_output round-trip cleanly
	history := []vault.AIChatMessage{
		{Role: "user", Content: "check srv-1"},
		{
			Role:             "assistant",
			ReasoningContent: turn1.ReasoningContent,
			ProviderState:    turn1.ProviderState,
			ToolCalls:        []vault.AIToolCallRecord{{ID: "call_resp_1", Name: "probe_server", Arguments: `{"server_id":"srv-1"}`}},
		},
		{Role: "tool", ToolCallID: "call_resp_1", ToolName: "probe_server", Content: `{"cpu":12}`},
	}
	turn2, err := client.StreamChat(context.Background(), prov, "SRE prompt", history, nil, StreamCallbacks{})
	if err != nil || turn2.Content != "巡检完毕，一切正常。" {
		t.Fatalf("Responses turn2 failed: turn=%+v err=%v", turn2, err)
	}
	inp, _ := captured[1]["input"].([]any)
	hasReasoning, hasFnCall, hasFnOut := false, false, false
	for _, it := range inp {
		m, _ := it.(map[string]any)
		switch m["type"] {
		case "reasoning":
			if m["encrypted_content"] == "enc_abc123" {
				hasReasoning = true
			}
		case "function_call":
			if m["call_id"] == "call_resp_1" {
				hasFnCall = true
			}
		case "function_call_output":
			if m["call_id"] == "call_resp_1" {
				hasFnOut = true
			}
		}
	}
	if !hasReasoning || !hasFnCall || !hasFnOut {
		t.Fatalf("Responses round-trip missing items: reasoning=%v fnCall=%v fnOut=%v", hasReasoning, hasFnCall, hasFnOut)
	}
}

func TestAnthropicAdaptiveThinkingAndGeminiThoughtSignatureRoundTrip(t *testing.T) {
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

	var anthCaptured []map[string]any
	var gemCaptured []map[string]any
	var anthAuthHeader string
	var gemQueryKey string

	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)

		switch {
		case r.URL.Path == "/custom/claude/messages":
			anthAuthHeader = r.Header.Get("Authorization")
			anthCaptured = append(anthCaptured, body)
			w.Header().Set("Content-Type", "text/event-stream")
			flusher := w.(http.Flusher)
			if len(anthCaptured) == 1 {
				evs := []string{
					`{"type":"message_start","message":{"usage":{"input_tokens":150,"cache_read_input_tokens":40}}}`,
					`{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`,
					`{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"思考方案"}}`,
					`{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig_ant_999"}}`,
					`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"probe_server","input":{}}}`,
					`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"server_id\":\"s1\"}"}}`,
					`{"type":"message_delta","usage":{"output_tokens":55}}`,
					`{"type":"message_stop"}`,
				}
				for _, e := range evs {
					_, _ = fmt.Fprintf(w, "data: %s\n\n", e)
					flusher.Flush()
				}
				return
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":"完成分析"}}`)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", `{"type":"message_stop"}`)
			flusher.Flush()

		case strings.Contains(r.URL.Path, ":streamGenerateContent"):
			if r.URL.Query().Get("alt") != "sse" {
				http.Error(w, "expected alt=sse", http.StatusBadRequest)
				return
			}
			gemQueryKey = r.URL.Query().Get("key")
			gemCaptured = append(gemCaptured, body)
			w.Header().Set("Content-Type", "text/event-stream")
			flusher := w.(http.Flusher)
			if len(gemCaptured) == 1 {
				evs := []string{
					`{"candidates":[{"content":{"parts":[{"text":"Gemini 推理中...","thought":true}]}}]}`,
					`{"candidates":[{"content":{"parts":[{"functionCall":{"name":"probe_server","args":{"server_id":"s1"}},"thoughtSignature":"gem_sig_xyz789"}]}}],"usageMetadata":{"promptTokenCount":180,"candidatesTokenCount":25,"thoughtsTokenCount":40,"cachedContentTokenCount":20,"totalTokenCount":245}}`,
				}
				for _, e := range evs {
					_, _ = fmt.Fprintf(w, "data: %s\n\n", e)
					flusher.Flush()
				}
				return
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", `{"candidates":[{"content":{"parts":[{"text":"Gemini 完成诊断"}]}}],"usageMetadata":{"promptTokenCount":220,"candidatesTokenCount":12,"totalTokenCount":232}}`)
			flusher.Flush()

		default:
			http.NotFound(w, r)
		}
	}))
	defer mock.Close()

	client := NewLLMClient()

	// 1. Anthropic Claude 5.5 via 3rd-party relay (Exact URL + Bearer Auth + Adaptive Thinking + Signature Round-Trip)
	anthProv := vault.AIProviderConfig{
		Protocol:        vault.AIProtocolAnthropic,
		BaseURL:         mock.URL + "/custom/claude/messages",
		EndpointMode:    vault.AIEndpointModeExact,
		AuthMode:        vault.AIAuthModeBearer,
		APIKey:          "sk-relay-claude",
		Model:           "claude-sonnet-5-5",
		MaxOutputTokens: 0, // unset -> auto-filled from catalog (128000) because Anthropic mandates max_tokens
		ReasoningEffort: vault.AIReasoningHigh,
		Temperature:     floatPtr(0.7), // must be omitted when thinking is enabled / temp=false
	}
	aTurn1, err := client.StreamChat(context.Background(), anthProv, "sys", []vault.AIChatMessage{
		{Role: "user", Content: "check"},
	}, nil, StreamCallbacks{})
	if err != nil {
		t.Fatalf("Anthropic turn1 failed: %v", err)
	}
	if anthAuthHeader != "Bearer sk-relay-claude" {
		t.Fatalf("expected Bearer auth header on Claude relay, got %q", anthAuthHeader)
	}
	if anthCaptured[0]["max_tokens"] != float64(128000) {
		t.Fatalf("expected auto max_tokens=128000 for claude-sonnet-5-5, got %v", anthCaptured[0]["max_tokens"])
	}
	if _, hasTemp := anthCaptured[0]["temperature"]; hasTemp {
		t.Fatalf("expected temperature omitted on claude-sonnet-5-5 with adaptive thinking")
	}
	thinkingObj, _ := anthCaptured[0]["thinking"].(map[string]any)
	outCfgObj, _ := anthCaptured[0]["output_config"].(map[string]any)
	if thinkingObj["type"] != "adaptive" || outCfgObj["effort"] != "high" {
		t.Fatalf("expected adaptive thinking + effort=high, got thinking=%+v output_config=%+v", thinkingObj, outCfgObj)
	}
	if aTurn1.ReasoningContent != "思考方案" || aTurn1.ProviderState == nil || len(aTurn1.ProviderState.AnthropicThinking) != 1 || aTurn1.ProviderState.AnthropicThinking[0].Signature != "sig_ant_999" {
		t.Fatalf("unexpected Anthropic thinking state: %+v", aTurn1)
	}

	// Turn 2: verify thinking block + signature echoed back before tool_use
	_, err = client.StreamChat(context.Background(), anthProv, "sys", []vault.AIChatMessage{
		{Role: "user", Content: "check"},
		{Role: "assistant", ReasoningContent: aTurn1.ReasoningContent, ProviderState: aTurn1.ProviderState, ToolCalls: []vault.AIToolCallRecord{{ID: "toolu_1", Name: "probe_server", Arguments: `{"server_id":"s1"}`}}},
		{Role: "tool", ToolCallID: "toolu_1", Content: "ok"},
	}, nil, StreamCallbacks{})
	if err != nil {
		t.Fatalf("Anthropic turn2 failed: %v", err)
	}
	msgs2, _ := anthCaptured[1]["messages"].([]any)
	asst2, _ := msgs2[1].(map[string]any)
	blocks2, _ := asst2["content"].([]any)
	firstBlk, _ := blocks2[0].(map[string]any)
	if firstBlk["type"] != "thinking" || firstBlk["signature"] != "sig_ant_999" {
		t.Fatalf("expected thinking block with signature preserved on turn2, got %+v", blocks2)
	}

	// 2. Google Gemini 4 Neon via query_key auth + thinkingLevel=xhigh + thoughtSignature round-trip
	gemProv := vault.AIProviderConfig{
		Protocol:        vault.AIProtocolGemini,
		BaseURL:         mock.URL + "/v1beta",
		AuthMode:        vault.AIAuthModeQueryKey,
		APIKey:          "AIza-test-key",
		Model:           "gemini-4-neon",
		ReasoningEffort: vault.AIReasoningMax,
	}
	gTurn1, err := client.StreamChat(context.Background(), gemProv, "sys prompt", []vault.AIChatMessage{
		{Role: "user", Content: "diagnose s1"},
	}, []ToolDefinition{{
		Name:        "probe_server",
		Description: "probe",
		Parameters: map[string]any{
			"$schema":              "http://json-schema.org/draft-07/schema#",
			"additionalProperties": false,
			"type":                 "object",
			"properties": map[string]any{
				"server_id": map[string]any{"type": "string", "default": "s1"},
			},
		},
	}}, StreamCallbacks{})
	if err != nil {
		t.Fatalf("Gemini turn1 failed: %v", err)
	}
	if gemQueryKey != "AIza-test-key" {
		t.Fatalf("expected ?key=AIza-test-key, got %q", gemQueryKey)
	}
	if gTurn1.ReasoningContent != "Gemini 推理中..." || len(gTurn1.ToolCalls) != 1 || gTurn1.ToolCalls[0].Name != "probe_server" {
		t.Fatalf("unexpected Gemini turn1: %+v", gTurn1)
	}
	if gTurn1.Usage == nil || gTurn1.Usage.ReasoningTokens != 40 || gTurn1.Usage.CachedInputTokens != 20 {
		t.Fatalf("unexpected Gemini usage: %+v", gTurn1.Usage)
	}
	genCfg, _ := gemCaptured[0]["generationConfig"].(map[string]any)
	tCfg, _ := genCfg["thinkingConfig"].(map[string]any)
	if tCfg["thinkingLevel"] != "xhigh" || tCfg["includeThoughts"] != true {
		t.Fatalf("expected Gemini 4 thinkingLevel=xhigh + includeThoughts=true, got %+v", tCfg)
	}
	// Verify schema sanitization stripped $schema / additionalProperties / default
	toolsArr, _ := gemCaptured[0]["tools"].([]any)
	fnDecls, _ := toolsArr[0].(map[string]any)["functionDeclarations"].([]any)
	fnParams, _ := fnDecls[0].(map[string]any)["parameters"].(map[string]any)
	if _, bad := fnParams["$schema"]; bad {
		t.Fatalf("expected $schema stripped from Gemini tool schema")
	}

	// Turn 2: verify thoughtSignature echoed on model functionCall part & tool mapped to functionResponse
	gTurn2, err := client.StreamChat(context.Background(), gemProv, "sys prompt", []vault.AIChatMessage{
		{Role: "user", Content: "diagnose s1"},
		{Role: "assistant", ProviderState: gTurn1.ProviderState, ToolCalls: []vault.AIToolCallRecord{{ID: gTurn1.ToolCalls[0].ID, Name: "probe_server", Arguments: gTurn1.ToolCalls[0].Arguments}}},
		{Role: "tool", ToolCallID: gTurn1.ToolCalls[0].ID, ToolName: "probe_server", Content: `{"ok":true}`},
	}, nil, StreamCallbacks{})
	if err != nil || gTurn2.Content != "Gemini 完成诊断" {
		t.Fatalf("Gemini turn2 failed: turn=%+v err=%v", gTurn2, err)
	}
	gContents, _ := gemCaptured[1]["contents"].([]any)
	modelTurn, _ := gContents[1].(map[string]any)
	modelParts, _ := modelTurn["parts"].([]any)
	fcPart, _ := modelParts[0].(map[string]any)
	if fcPart["thoughtSignature"] != "gem_sig_xyz789" {
		t.Fatalf("expected Gemini thoughtSignature echoed verbatim, got %+v", fcPart)
	}
	toolTurn, _ := gContents[2].(map[string]any)
	toolParts, _ := toolTurn["parts"].([]any)
	frObj, _ := toolParts[0].(map[string]any)["functionResponse"].(map[string]any)
	if frObj["name"] != "probe_server" {
		t.Fatalf("expected Gemini functionResponse name=probe_server, got %+v", frObj)
	}
}

func TestModelCatalogSyncDiscoveryUnrestrictedConfigAndCloneSecurity(t *testing.T) {
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/catalog/models.dev.json":
			_, _ = w.Write([]byte(`{
				"openai": {
					"name": "OpenAI",
					"models": {
						"gpt-7-preview": {
							"name": "GPT-7 Preview",
							"release_date": "2026-11-26",
							"reasoning": true,
							"tool_call": true,
							"temperature": false,
							"limit": {"context": 2000000, "input": 1800000, "output": 200000}
						}
					}
				}
			}`))
		case "/v1/models":
			_, _ = w.Write([]byte(`{"data":[{"id":"gpt-7-preview"},{"id":"custom-local-99b","context_length":262144,"max_output_tokens":32768}]}`))
		case "/v1beta/models":
			_, _ = w.Write([]byte(`{"models":[{"name":"models/gemini-4-neon","displayName":"Gemini 4 Neon","inputTokenLimit":1048576,"outputTokenLimit":65536,"supportedGenerationMethods":["generateContent"]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer mock.Close()

	store, err := vault.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Setup("StrongMasterPass!2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	client := NewLLMClient()
	// 1. Sync public model catalog from mock models.dev URL & save to runtime store
	cache, err := SyncPublicModelCatalog(context.Background(), client.Transport(), mock.URL+"/catalog/models.dev.json")
	if err != nil || len(cache.Models) != 1 || cache.Models[0].ID != "gpt-7-preview" {
		t.Fatalf("SyncPublicModelCatalog failed: cache=%+v err=%v", cache, err)
	}
	if err := store.SaveModelCatalogCache(*cache); err != nil {
		t.Fatalf("SaveModelCatalogCache: %v", err)
	}
	spec := LookupModelSpec("gpt-7-preview", vault.AIProtocolOpenAIResponses, store.GetModelCatalogCache())
	if spec.ContextWindow != 2000000 || spec.MaxInputTokens != 1800000 || spec.MaxOutputTokens != 200000 || spec.SupportsTemperature {
		t.Fatalf("unexpected synced model spec: %+v", spec)
	}

	// 2. Discover models via /v1/models and Gemini /v1beta/models
	oaModels, err := FetchProviderModels(context.Background(), client.Transport(), vault.AIProviderConfig{
		Protocol: vault.AIProtocolOpenAI,
		BaseURL:  mock.URL + "/v1",
	}, store.GetModelCatalogCache())
	if err != nil || len(oaModels) != 2 {
		t.Fatalf("FetchProviderModels openai failed: models=%+v err=%v", oaModels, err)
	}
	gemModels, err := FetchProviderModels(context.Background(), client.Transport(), vault.AIProviderConfig{
		Protocol: vault.AIProtocolGemini,
		BaseURL:  mock.URL + "/v1beta",
	}, store.GetModelCatalogCache())
	if err != nil || len(gemModels) != 1 || gemModels[0].ID != "gemini-4-neon" || gemModels[0].MaxInputTokens != 1048576 {
		t.Fatalf("FetchProviderModels gemini failed: models=%+v err=%v", gemModels, err)
	}

	// 3. Unrestricted huge token limits + encrypted custom headers + clone security guard
	hdrs := []vault.AICustomHeader{
		{Key: "X-Custom-Token", Value: "super-secret-hdr-val-7788"},
		{Key: "X-Title", Value: "ServerNeedSafe"},
	}
	pv, _, err := store.UpsertAIProvider(vault.AIProviderMutationInput{
		Name:            "Unrestricted Relay",
		Protocol:        vault.AIProtocolGemini,
		BaseURL:         "https://relay.internal.example/v1beta",
		EndpointMode:    vault.AIEndpointModeAuto,
		AuthMode:        vault.AIAuthModeBearer,
		APIKey:          strPtr("sk-unrestricted-key-112233"),
		Model:           "gemini-4-neon",
		ContextWindow:   10000000,
		MaxInputTokens:  9000000,
		MaxOutputTokens: intPtr(500000),
		Temperature:     floatPtr(0.35),
		TopP:            floatPtr(0.95),
		ReasoningEffort: vault.AIReasoningHigh,
		CustomHeaders:   &hdrs,
		ExtraBodyJSON:   `{"safetySettings":[]}`,
		SetActive:       true,
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpsertAIProvider unrestricted failed: %v", err)
	}
	if pv.ContextWindow != 10000000 || pv.MaxInputTokens != 9000000 || pv.MaxOutputTokens != 500000 {
		t.Fatalf("expected unrestricted token limits preserved, got ctx=%d in=%d out=%d", pv.ContextWindow, pv.MaxInputTokens, pv.MaxOutputTokens)
	}
	if len(pv.CustomHeaders) != 2 || !pv.CustomHeaders[0].IsSensitive || strings.Contains(pv.CustomHeaders[0].ValuePreview, "7788") && strings.Contains(pv.CustomHeaders[0].ValuePreview, "super-secret") {
		t.Fatalf("expected sensitive custom header masked in view, got %+v", pv.CustomHeaders)
	}

	// Clone for same endpoint with a different model -> inherits encrypted APIKey & sensitive header cleanly!
	cloned, _, err := store.UpsertAIProvider(vault.AIProviderMutationInput{
		CloneFromID: pv.ID,
		Name:        "Unrestricted Relay - Hydrogen",
		Protocol:    vault.AIProtocolGemini,
		BaseURL:     "https://relay.internal.example/v1beta",
		Model:       "gemini-4-hydrogen",
	}, "127.0.0.1")
	if err != nil || !cloned.HasAPIKey {
		t.Fatalf("expected safe clone for identical endpoint to inherit key: cloned=%+v err=%v", cloned, err)
	}

	// Clone attempting to repoint to an attacker URL without re-entering API key -> MUST be rejected!
	if _, _, err := store.UpsertAIProvider(vault.AIProviderMutationInput{
		CloneFromID: pv.ID,
		Name:        "Evil Clone",
		Protocol:    vault.AIProtocolGemini,
		BaseURL:     "https://evil.attacker.example/v1beta",
		Model:       "gemini-4-hydrogen",
	}, "127.0.0.1"); err == nil {
		t.Fatalf("SECURITY FAILURE: allowed cloning stored API key to a different BaseURL!")
	}

	// Verify ZERO plaintext secret leakage on disk
	if err := store.FlushNow(); err != nil {
		t.Fatalf("FlushNow: %v", err)
	}
	rawSec, _ := os.ReadFile(store.SecretsPath())
	rawRT, _ := os.ReadFile(filepath.Join(store.DataDir(), "aiops_runtime.json"))
	for _, secret := range []string{"sk-unrestricted-key-112233", "super-secret-hdr-val-7788"} {
		if bytes.Contains(rawSec, []byte(secret)) || bytes.Contains(rawRT, []byte(secret)) {
			t.Fatalf("SECURITY FAILURE: secret %q leaked in plaintext on disk!", secret)
		}
	}
}
