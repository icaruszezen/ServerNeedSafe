package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAIProviderModernEndpointsCatalogSyncModelsAndCloneSecurity(t *testing.T) {
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

	var attackerHits atomic.Int32
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerHits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer attacker.Close()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/catalog.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"google/gemini-4-neon","name":"Gemini 4 Neon","context_length":1048576,"top_provider":{"context_length":1048576,"max_completion_tokens":65536},"supported_parameters":["reasoning","tools","temperature"]}]}`))

		case r.URL.Path == "/v1beta/models":
			if r.Header.Get("x-goog-api-key") != "AIza-secret-9988" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"models":[{"name":"models/gemini-4-neon","displayName":"Gemini 4 Neon","inputTokenLimit":1048576,"outputTokenLimit":65536,"supportedGenerationMethods":["generateContent"]}]}`))

		case strings.Contains(r.URL.Path, ":streamGenerateContent"):
			if r.Header.Get("x-goog-api-key") != "AIza-secret-9988" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			flusher := w.(http.Flusher)
			_, _ = fmt.Fprint(w, "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"自检思考\",\"thought\":true}]}}]}\n\n")
			_, _ = fmt.Fprint(w, "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"连接正常\"}]}}],\"usageMetadata\":{\"promptTokenCount\":22,\"candidatesTokenCount\":4,\"thoughtsTokenCount\":8,\"totalTokenCount\":34}}\n\n")
			flusher.Flush()

		default:
			http.NotFound(w, r)
		}
	}))
	defer mockUpstream.Close()

	srv, ts := newTestServerInstance(t, t.TempDir(), 8*time.Hour)
	defer ts.Close()
	defer srv.Close()

	client := newCookieHTTPClient()
	setupAdminForRegression(t, ts, client, "ModernAIAdmin#2026!")

	// 1. Sync public model catalog via API
	syncBody, _ := json.Marshal(map[string]any{"custom_url": mockUpstream.URL + "/catalog.json"})
	res, err := client.Post(ts.URL+"/api/ai/model-catalog/sync", "application/json", bytes.NewReader(syncBody))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/ai/model-catalog/sync: status=%v err=%v", res.StatusCode, err)
	}
	var syncOut struct {
		OK           bool `json:"ok"`
		ModelCatalog struct {
			Source      string `json:"source"`
			SyncedCount int    `json:"synced_count"`
		} `json:"model_catalog"`
	}
	_ = json.NewDecoder(res.Body).Decode(&syncOut)
	res.Body.Close()
	if !syncOut.OK || syncOut.ModelCatalog.SyncedCount != 1 || syncOut.ModelCatalog.Source != "openrouter" {
		t.Fatalf("unexpected sync response: %+v", syncOut)
	}

	// 2. Create Gemini provider with unrestricted limits & custom headers
	createBody, _ := json.Marshal(map[string]any{
		"name":              "Gemini 4 Prod",
		"protocol":          "gemini",
		"base_url":          mockUpstream.URL + "/v1beta",
		"auth_mode":         "x-goog-api-key",
		"api_key":           "AIza-secret-9988",
		"model":             "gemini-4-neon",
		"context_window":    2097152,
		"max_input_tokens":  1900000,
		"max_output_tokens": 131072,
		"reasoning_effort":  "high",
		"custom_headers": []map[string]string{
			{"key": "X-Proxy-Token", "value": "proxy-secret-xyz"},
			{"key": "X-App-Name", "value": "ServerNeedSafe"},
		},
		"extra_body_json": `{"generationConfig":{"topK":40}}`,
		"set_active":      true,
	})
	res, err = client.Post(ts.URL+"/api/ai/providers", "application/json", bytes.NewReader(createBody))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/ai/providers gemini: status=%v err=%v", res.StatusCode, err)
	}
	var created struct {
		Provider struct {
			ID              string `json:"id"`
			ContextWindow   int    `json:"context_window"`
			MaxInputTokens  int    `json:"max_input_tokens"`
			MaxOutputTokens int    `json:"max_output_tokens"`
		} `json:"provider"`
	}
	_ = json.NewDecoder(res.Body).Decode(&created)
	res.Body.Close()
	if created.Provider.ContextWindow != 2097152 || created.Provider.MaxInputTokens != 1900000 || created.Provider.MaxOutputTokens != 131072 {
		t.Fatalf("expected unrestricted limits persisted, got %+v", created.Provider)
	}

	// 3. Fetch /models using stored encrypted key for identical endpoint
	modelsReq, _ := json.Marshal(map[string]any{
		"id":       created.Provider.ID,
		"protocol": "gemini",
		"base_url": mockUpstream.URL + "/v1beta",
	})
	res, err = client.Post(ts.URL+"/api/ai/provider-models", "application/json", bytes.NewReader(modelsReq))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/ai/provider-models: status=%v err=%v", res.StatusCode, err)
	}
	var modelsOut struct {
		OK    bool `json:"ok"`
		Count int  `json:"count"`
	}
	_ = json.NewDecoder(res.Body).Decode(&modelsOut)
	res.Body.Close()
	if !modelsOut.OK || modelsOut.Count != 1 {
		t.Fatalf("unexpected provider-models output: %+v", modelsOut)
	}

	// 4. Security guard: /api/ai/provider-models must NOT send stored key to attacker URL!
	evilModelsReq, _ := json.Marshal(map[string]any{
		"id":       created.Provider.ID,
		"protocol": "gemini",
		"base_url": attacker.URL + "/v1beta",
	})
	if code := doWithHeaders(t, client, http.MethodPost, ts.URL+"/api/ai/provider-models", evilModelsReq, nil); code != http.StatusBadRequest {
		t.Fatalf("expected 400 rejecting provider-models against repointed URL, got %d", code)
	}
	if attackerHits.Load() != 0 {
		t.Fatalf("SECURITY FAILURE: stored key sent to attacker via /api/ai/provider-models")
	}

	// 5. Streaming TestConnection against Gemini mock returns TTFT, reply, reasoning preview & usage
	testReq, _ := json.Marshal(map[string]any{
		"id":       created.Provider.ID,
		"protocol": "gemini",
		"base_url": mockUpstream.URL + "/v1beta",
		"model":    "gemini-4-neon",
	})
	res, err = client.Post(ts.URL+"/api/ai/test-provider", "application/json", bytes.NewReader(testReq))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/ai/test-provider gemini: status=%v err=%v", res.StatusCode, err)
	}
	var testOut struct {
		OK               bool   `json:"ok"`
		LatencyMs        int64  `json:"latency_ms"`
		FirstTokenMs     int64  `json:"first_token_ms"`
		Reply            string `json:"reply"`
		ReasoningPreview string `json:"reasoning_preview"`
		Usage            *struct {
			TotalTokens     int `json:"total_tokens"`
			ReasoningTokens int `json:"reasoning_tokens"`
		} `json:"usage"`
	}
	_ = json.NewDecoder(res.Body).Decode(&testOut)
	res.Body.Close()
	if !testOut.OK || testOut.Reply != "连接正常" || testOut.ReasoningPreview != "自检思考" || testOut.FirstTokenMs <= 0 || testOut.Usage == nil || testOut.Usage.ReasoningTokens != 8 {
		t.Fatalf("unexpected Gemini test-provider response: %+v", testOut)
	}
}
