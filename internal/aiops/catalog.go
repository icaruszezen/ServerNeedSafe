package aiops

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

const (
	defaultModelsDevCatalogURL  = "https://models.dev/api.json"
	defaultOpenRouterCatalogURL = "https://openrouter.ai/api/v1/models"
)

// ModelSpec captures resolved default token limits and protocol/parameter adaptation traits for a model.
type ModelSpec struct {
	ID                      string           `json:"id"`
	Name                    string           `json:"name,omitempty"`
	Vendor                  string           `json:"vendor,omitempty"`
	Protocol                vault.AIProtocol `json:"protocol,omitempty"`
	ContextWindow           int              `json:"context_window"`
	MaxInputTokens          int              `json:"max_input_tokens"`
	MaxOutputTokens         int              `json:"max_output_tokens"`
	SupportsReasoning       bool             `json:"supports_reasoning"`
	SupportsTemperature     bool             `json:"supports_temperature"`
	SupportsTools           bool             `json:"supports_tools"`
	InterleavedReasoningKey string           `json:"interleaved_reasoning_key,omitempty"`
	UseMaxCompletionTokens  bool             `json:"use_max_completion_tokens"`
	UseAdaptiveThinking     bool             `json:"use_adaptive_thinking"`
	GeminiUseThinkingLevel  bool             `json:"gemini_use_thinking_level"`
	Source                  string           `json:"source"`
}

func boolPtr(v bool) *bool { return &v }

// BuiltinModelCatalog returns an up-to-date offline snapshot of flagship and mainstream LLM defaults
// across OpenAI, Anthropic Claude, Google Gemini, DeepSeek, Alibaba Qwen, Moonshot Kimi, Zhipu GLM,
// xAI Grok, MiniMax, and local Ollama models.
func BuiltinModelCatalog() []vault.AIModelCatalogEntry {
	t := true
	f := false
	return []vault.AIModelCatalogEntry{
		// --- OpenAI (GPT-6 / GPT-5 / o-series / GPT-4.x) ---
		{ID: "gpt-6.2-sol", Name: "GPT-6.2 Sol", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAIResponses, ContextWindow: 1050000, MaxInputTokens: 922000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &f, SupportsTools: true, ReleaseDate: "2026-11-17", Source: "builtin"},
		{ID: "gpt-6.2-astra", Name: "GPT-6.2 Astra", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAIResponses, ContextWindow: 1050000, MaxInputTokens: 922000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &f, SupportsTools: true, ReleaseDate: "2026-11-17", Source: "builtin"},
		{ID: "gpt-6.1-terra", Name: "GPT-6.1 Terra", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAIResponses, ContextWindow: 1050000, MaxInputTokens: 922000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-10-26", Source: "builtin"},
		{ID: "gpt-6.1-sol", Name: "GPT-6.1 Sol", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAIResponses, ContextWindow: 1050000, MaxInputTokens: 922000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &f, SupportsTools: true, ReleaseDate: "2026-09-29", Source: "builtin"},
		{ID: "gpt-6-sol", Name: "GPT-6 Sol", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAIResponses, ContextWindow: 1050000, MaxInputTokens: 922000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-09-22", Source: "builtin"},
		{ID: "gpt-6-luna", Name: "GPT-6 Luna", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAIResponses, ContextWindow: 1050000, MaxInputTokens: 922000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-09-22", Source: "builtin"},
		{ID: "gpt-5.6", Name: "GPT-5.6", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAIResponses, ContextWindow: 1050000, MaxInputTokens: 922000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-07-09", Source: "builtin"},
		{ID: "gpt-5.5", Name: "GPT-5.5", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAIResponses, ContextWindow: 1050000, MaxInputTokens: 922000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-04-23", Source: "builtin"},
		{ID: "gpt-5.4", Name: "GPT-5.4", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAIResponses, ContextWindow: 1050000, MaxInputTokens: 922000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-03-05", Source: "builtin"},
		{ID: "gpt-5.4-mini", Name: "GPT-5.4 Mini", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAIResponses, ContextWindow: 400000, MaxInputTokens: 272000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-03-17", Source: "builtin"},
		{ID: "gpt-5.4-nano", Name: "GPT-5.4 Nano", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAIResponses, ContextWindow: 400000, MaxInputTokens: 272000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-03-17", Source: "builtin"},
		{ID: "gpt-5.3-codex", Name: "GPT-5.3 Codex", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAIResponses, ContextWindow: 400000, MaxInputTokens: 272000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-02-05", Source: "builtin"},
		{ID: "gpt-5.2", Name: "GPT-5.2", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAIResponses, ContextWindow: 400000, MaxInputTokens: 272000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-12-11", Source: "builtin"},
		{ID: "gpt-5.1", Name: "GPT-5.1", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAI, ContextWindow: 400000, MaxInputTokens: 272000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-11-13", Source: "builtin"},
		{ID: "gpt-5", Name: "GPT-5", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAI, ContextWindow: 400000, MaxInputTokens: 272000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &f, SupportsTools: true, ReleaseDate: "2025-08-07", Source: "builtin"},
		{ID: "gpt-5-mini", Name: "GPT-5 Mini", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAI, ContextWindow: 400000, MaxInputTokens: 272000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &f, SupportsTools: true, ReleaseDate: "2025-08-07", Source: "builtin"},
		{ID: "o3", Name: "OpenAI o3", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAI, ContextWindow: 200000, MaxInputTokens: 100000, MaxOutputTokens: 100000, SupportsReasoning: true, SupportsTemperature: &f, SupportsTools: true, ReleaseDate: "2025-04-16", Source: "builtin"},
		{ID: "o4-mini", Name: "OpenAI o4-mini", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAI, ContextWindow: 200000, MaxInputTokens: 100000, MaxOutputTokens: 100000, SupportsReasoning: true, SupportsTemperature: &f, SupportsTools: true, ReleaseDate: "2025-04-16", Source: "builtin"},
		{ID: "gpt-4.1", Name: "GPT-4.1", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1047576, MaxInputTokens: 1014808, MaxOutputTokens: 32768, SupportsReasoning: false, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-04-14", Source: "builtin"},
		{ID: "gpt-4.1-mini", Name: "GPT-4.1 Mini", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1047576, MaxInputTokens: 1014808, MaxOutputTokens: 32768, SupportsReasoning: false, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-04-14", Source: "builtin"},
		{ID: "gpt-4o", Name: "GPT-4o", Vendor: "OpenAI", Protocol: vault.AIProtocolOpenAI, ContextWindow: 128000, MaxInputTokens: 111616, MaxOutputTokens: 16384, SupportsReasoning: false, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2024-11-20", Source: "builtin"},

		// --- Anthropic Claude (5.x / 4.x / 3.x) ---
		{ID: "claude-sonnet-5-5", Name: "Claude Sonnet 5.5", Vendor: "Anthropic", Protocol: vault.AIProtocolAnthropic, ContextWindow: 1000000, MaxInputTokens: 872000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &f, SupportsTools: true, ReleaseDate: "2026-09-28", Source: "builtin"},
		{ID: "claude-opus-5-5", Name: "Claude Opus 5.5", Vendor: "Anthropic", Protocol: vault.AIProtocolAnthropic, ContextWindow: 1000000, MaxInputTokens: 872000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &f, SupportsTools: true, ReleaseDate: "2026-09-22", Source: "builtin"},
		{ID: "claude-haiku-5-5", Name: "Claude Haiku 5.5", Vendor: "Anthropic", Protocol: vault.AIProtocolAnthropic, ContextWindow: 1000000, MaxInputTokens: 872000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &f, SupportsTools: true, ReleaseDate: "2026-10-07", Source: "builtin"},
		{ID: "claude-fable-5-2", Name: "Claude Fable 5.2", Vendor: "Anthropic", Protocol: vault.AIProtocolAnthropic, ContextWindow: 1000000, MaxInputTokens: 872000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &f, SupportsTools: true, ReleaseDate: "2026-11-09", Source: "builtin"},
		{ID: "claude-opus-5", Name: "Claude Opus 5", Vendor: "Anthropic", Protocol: vault.AIProtocolAnthropic, ContextWindow: 1000000, MaxInputTokens: 872000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &f, SupportsTools: true, ReleaseDate: "2026-07-24", Source: "builtin"},
		{ID: "claude-sonnet-5", Name: "Claude Sonnet 5", Vendor: "Anthropic", Protocol: vault.AIProtocolAnthropic, ContextWindow: 1000000, MaxInputTokens: 872000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &f, SupportsTools: true, ReleaseDate: "2026-06-29", Source: "builtin"},
		{ID: "claude-opus-4-8", Name: "Claude Opus 4.8", Vendor: "Anthropic", Protocol: vault.AIProtocolAnthropic, ContextWindow: 1000000, MaxInputTokens: 872000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &f, SupportsTools: true, ReleaseDate: "2026-05-28", Source: "builtin"},
		{ID: "claude-opus-4-7", Name: "Claude Opus 4.7", Vendor: "Anthropic", Protocol: vault.AIProtocolAnthropic, ContextWindow: 1000000, MaxInputTokens: 872000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &f, SupportsTools: true, ReleaseDate: "2026-04-14", Source: "builtin"},
		{ID: "claude-sonnet-4-6", Name: "Claude Sonnet 4.6", Vendor: "Anthropic", Protocol: vault.AIProtocolAnthropic, ContextWindow: 1000000, MaxInputTokens: 872000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-02-17", Source: "builtin"},
		{ID: "claude-opus-4-6", Name: "Claude Opus 4.6", Vendor: "Anthropic", Protocol: vault.AIProtocolAnthropic, ContextWindow: 1000000, MaxInputTokens: 872000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-02-04", Source: "builtin"},
		{ID: "claude-sonnet-4-5", Name: "Claude Sonnet 4.5", Vendor: "Anthropic", Protocol: vault.AIProtocolAnthropic, ContextWindow: 200000, MaxInputTokens: 136000, MaxOutputTokens: 64000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-09-29", Source: "builtin"},
		{ID: "claude-opus-4-5", Name: "Claude Opus 4.5", Vendor: "Anthropic", Protocol: vault.AIProtocolAnthropic, ContextWindow: 200000, MaxInputTokens: 136000, MaxOutputTokens: 64000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-11-24", Source: "builtin"},
		{ID: "claude-haiku-4-5", Name: "Claude Haiku 4.5", Vendor: "Anthropic", Protocol: vault.AIProtocolAnthropic, ContextWindow: 200000, MaxInputTokens: 136000, MaxOutputTokens: 64000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-10-15", Source: "builtin"},
		{ID: "claude-3-7-sonnet", Name: "Claude 3.7 Sonnet", Vendor: "Anthropic", Protocol: vault.AIProtocolAnthropic, ContextWindow: 200000, MaxInputTokens: 136000, MaxOutputTokens: 64000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-02-24", Source: "builtin"},

		// --- Google Gemini (4 / 3.x / 2.5 / Gemma 4) ---
		{ID: "gemini-4-neon", Name: "Gemini 4 Neon", Vendor: "Google", Protocol: vault.AIProtocolGemini, ContextWindow: 1048576, MaxInputTokens: 983040, MaxOutputTokens: 65536, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-11-18", Source: "builtin"},
		{ID: "gemini-4-hydrogen", Name: "Gemini 4 Hydrogen", Vendor: "Google", Protocol: vault.AIProtocolGemini, ContextWindow: 1048576, MaxInputTokens: 983040, MaxOutputTokens: 65536, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-11-12", Source: "builtin"},
		{ID: "gemini-4-carbon", Name: "Gemini 4 Carbon", Vendor: "Google", Protocol: vault.AIProtocolGemini, ContextWindow: 1048576, MaxInputTokens: 1015808, MaxOutputTokens: 32768, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-11-10", Source: "builtin"},
		{ID: "gemini-4-argon", Name: "Gemini 4 Argon", Vendor: "Google", Protocol: vault.AIProtocolGemini, ContextWindow: 1048576, MaxInputTokens: 1015808, MaxOutputTokens: 32768, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-10-13", Source: "builtin"},
		{ID: "gemini-3.8-flash", Name: "Gemini 3.8 Flash", Vendor: "Google", Protocol: vault.AIProtocolGemini, ContextWindow: 1048576, MaxInputTokens: 983040, MaxOutputTokens: 65536, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-09-02", Source: "builtin"},
		{ID: "gemini-3.7-flash", Name: "Gemini 3.7 Flash", Vendor: "Google", Protocol: vault.AIProtocolGemini, ContextWindow: 1048576, MaxInputTokens: 983040, MaxOutputTokens: 65536, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-08-13", Source: "builtin"},
		{ID: "gemini-3.5-flash", Name: "Gemini 3.5 Flash", Vendor: "Google", Protocol: vault.AIProtocolGemini, ContextWindow: 1048576, MaxInputTokens: 983040, MaxOutputTokens: 65536, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-05-19", Source: "builtin"},
		{ID: "gemini-3.1-pro-preview", Name: "Gemini 3.1 Pro Preview", Vendor: "Google", Protocol: vault.AIProtocolGemini, ContextWindow: 1048576, MaxInputTokens: 983040, MaxOutputTokens: 65536, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-02-19", Source: "builtin"},
		{ID: "gemini-3-flash-preview", Name: "Gemini 3 Flash Preview", Vendor: "Google", Protocol: vault.AIProtocolGemini, ContextWindow: 1048576, MaxInputTokens: 983040, MaxOutputTokens: 65536, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-12-17", Source: "builtin"},
		{ID: "gemini-flash-latest", Name: "Gemini Flash Latest", Vendor: "Google", Protocol: vault.AIProtocolGemini, ContextWindow: 1048576, MaxInputTokens: 983040, MaxOutputTokens: 65536, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-09-02", Source: "builtin"},
		{ID: "gemini-pro-latest", Name: "Gemini Pro Latest", Vendor: "Google", Protocol: vault.AIProtocolGemini, ContextWindow: 1048576, MaxInputTokens: 983040, MaxOutputTokens: 65536, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-02-19", Source: "builtin"},
		{ID: "gemini-2.5-pro", Name: "Gemini 2.5 Pro", Vendor: "Google", Protocol: vault.AIProtocolGemini, ContextWindow: 1048576, MaxInputTokens: 983040, MaxOutputTokens: 65536, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-06-17", Source: "builtin"},
		{ID: "gemini-2.5-flash", Name: "Gemini 2.5 Flash", Vendor: "Google", Protocol: vault.AIProtocolGemini, ContextWindow: 1048576, MaxInputTokens: 983040, MaxOutputTokens: 65536, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-06-17", Source: "builtin"},
		{ID: "gemini-2.5-flash-lite", Name: "Gemini 2.5 Flash Lite", Vendor: "Google", Protocol: vault.AIProtocolGemini, ContextWindow: 1048576, MaxInputTokens: 983040, MaxOutputTokens: 65536, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-07-22", Source: "builtin"},

		// --- DeepSeek (V4 / V3.2 / R1) ---
		{ID: "deepseek-v4-pro", Name: "DeepSeek V4 Pro", Vendor: "DeepSeek", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1048576, MaxInputTokens: 655360, MaxOutputTokens: 393216, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2026-08-13", Source: "builtin"},
		{ID: "deepseek-v4-flash", Name: "DeepSeek V4 Flash", Vendor: "DeepSeek", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1048576, MaxInputTokens: 655360, MaxOutputTokens: 393216, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2026-10-17", Source: "builtin"},
		{ID: "deepseek-flash", Name: "DeepSeek Flash", Vendor: "DeepSeek", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1048576, MaxInputTokens: 655360, MaxOutputTokens: 393216, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2026-10-17", Source: "builtin"},
		{ID: "deepseek-chat", Name: "DeepSeek Chat", Vendor: "DeepSeek", Protocol: vault.AIProtocolOpenAI, ContextWindow: 131072, MaxInputTokens: 122880, MaxOutputTokens: 8192, SupportsReasoning: false, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2025-12-01", Source: "builtin"},
		{ID: "deepseek-reasoner", Name: "DeepSeek Reasoner", Vendor: "DeepSeek", Protocol: vault.AIProtocolOpenAI, ContextWindow: 131072, MaxInputTokens: 65536, MaxOutputTokens: 65536, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2025-12-01", Source: "builtin"},
		{ID: "deepseek-v3.2", Name: "DeepSeek V3.2", Vendor: "DeepSeek", Protocol: vault.AIProtocolOpenAI, ContextWindow: 131072, MaxInputTokens: 65536, MaxOutputTokens: 65536, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2025-12-01", Source: "builtin"},
		{ID: "deepseek-r1", Name: "DeepSeek R1", Vendor: "DeepSeek", Protocol: vault.AIProtocolOpenAI, ContextWindow: 131072, MaxInputTokens: 114688, MaxOutputTokens: 16384, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2025-05-28", Source: "builtin"},

		// --- Alibaba Qwen (Qwen4 / Qwen3.x) ---
		{ID: "qwen4-max", Name: "Qwen4 Max", Vendor: "Alibaba Qwen", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1000000, MaxInputTokens: 737856, MaxOutputTokens: 262144, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2026-11-16", Source: "builtin"},
		{ID: "qwen3.8-max", Name: "Qwen3.8 Max", Vendor: "Alibaba Qwen", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1000000, MaxInputTokens: 868928, MaxOutputTokens: 131072, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2026-08-03", Source: "builtin"},
		{ID: "qwen3.8-flash", Name: "Qwen3.8 Flash", Vendor: "Alibaba Qwen", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1000000, MaxInputTokens: 868928, MaxOutputTokens: 131072, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2026-08-26", Source: "builtin"},
		{ID: "qwen3.7-max", Name: "Qwen3.7 Max", Vendor: "Alibaba Qwen", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1000000, MaxInputTokens: 868928, MaxOutputTokens: 131072, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2026-05-21", Source: "builtin"},
		{ID: "qwen3.7-plus", Name: "Qwen3.7 Plus", Vendor: "Alibaba Qwen", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1000000, MaxInputTokens: 868928, MaxOutputTokens: 131072, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2026-06-02", Source: "builtin"},
		{ID: "qwen3.7-flash", Name: "Qwen3.7 Flash", Vendor: "Alibaba Qwen", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1000000, MaxInputTokens: 991808, MaxOutputTokens: 131072, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2026-07-15", Source: "builtin"},
		{ID: "qwen3.5-plus", Name: "Qwen3.5 Plus", Vendor: "Alibaba Qwen", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1000000, MaxInputTokens: 934464, MaxOutputTokens: 65536, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2026-02-16", Source: "builtin"},
		{ID: "qwen3-coder-flash", Name: "Qwen3 Coder Flash", Vendor: "Alibaba Qwen", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1000000, MaxInputTokens: 934464, MaxOutputTokens: 65536, SupportsReasoning: false, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-07-28", Source: "builtin"},
		{ID: "qwen-max", Name: "Qwen Max", Vendor: "Alibaba Qwen", Protocol: vault.AIProtocolOpenAI, ContextWindow: 131072, MaxInputTokens: 122880, MaxOutputTokens: 8192, SupportsReasoning: false, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-01-25", Source: "builtin"},
		{ID: "qwen-plus", Name: "Qwen Plus", Vendor: "Alibaba Qwen", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1000000, MaxInputTokens: 967232, MaxOutputTokens: 32768, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-07-28", Source: "builtin"},

		// --- Moonshot Kimi / Zhipu GLM / xAI Grok / MiniMax / Local Ollama ---
		{ID: "kimi-k3.1-pro", Name: "Kimi K3.1 Pro", Vendor: "Moonshot AI", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1048576, MaxInputTokens: 917504, MaxOutputTokens: 131072, SupportsReasoning: true, SupportsTemperature: &f, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2026-10-23", Source: "builtin"},
		{ID: "kimi-k3", Name: "Kimi K3", Vendor: "Moonshot AI", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1048576, MaxInputTokens: 917504, MaxOutputTokens: 131072, SupportsReasoning: true, SupportsTemperature: &f, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2026-07-16", Source: "builtin"},
		{ID: "kimi-k2.7-code", Name: "Kimi K2.7 Code", Vendor: "Moonshot AI", Protocol: vault.AIProtocolOpenAI, ContextWindow: 262144, MaxInputTokens: 196608, MaxOutputTokens: 65536, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2026-06-12", Source: "builtin"},
		{ID: "glm-5.3", Name: "GLM-5.3", Vendor: "Zhipu AI", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1000000, MaxInputTokens: 868928, MaxOutputTokens: 131072, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2026-08-14", Source: "builtin"},
		{ID: "glm-5.3-flash", Name: "GLM-5.3 Flash", Vendor: "Zhipu AI", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1000000, MaxInputTokens: 868928, MaxOutputTokens: 131072, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2026-08-26", Source: "builtin"},
		{ID: "glm-5.2", Name: "GLM-5.2", Vendor: "Zhipu AI", Protocol: vault.AIProtocolOpenAI, ContextWindow: 1000000, MaxInputTokens: 868928, MaxOutputTokens: 131072, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2026-06-13", Source: "builtin"},
		{ID: "grok-4.7", Name: "Grok 4.7", Vendor: "xAI", Protocol: vault.AIProtocolOpenAI, ContextWindow: 500000, MaxInputTokens: 372000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-09-21", Source: "builtin"},
		{ID: "grok-4.6", Name: "Grok 4.6", Vendor: "xAI", Protocol: vault.AIProtocolOpenAI, ContextWindow: 500000, MaxInputTokens: 372000, MaxOutputTokens: 128000, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-08-12", Source: "builtin"},
		{ID: "MiniMax-M2.7", Name: "MiniMax M2.7", Vendor: "MiniMax", Protocol: vault.AIProtocolOpenAI, ContextWindow: 204800, MaxInputTokens: 139264, MaxOutputTokens: 65536, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, InterleavedReasoningKey: "reasoning_content", ReleaseDate: "2026-03-18", Source: "builtin"},
		{ID: "qwen3:14b", Name: "Qwen3 14B (Ollama)", Vendor: "Ollama", Protocol: vault.AIProtocolOpenAI, ContextWindow: 40960, MaxInputTokens: 32768, MaxOutputTokens: 8192, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-04-29", Source: "builtin"},
		{ID: "qwen3:32b", Name: "Qwen3 32B (Ollama)", Vendor: "Ollama", Protocol: vault.AIProtocolOpenAI, ContextWindow: 40960, MaxInputTokens: 32768, MaxOutputTokens: 8192, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-04-29", Source: "builtin"},
		{ID: "gemma4:26b", Name: "Gemma 4 26B (Ollama)", Vendor: "Ollama", Protocol: vault.AIProtocolOpenAI, ContextWindow: 262144, MaxInputTokens: 229376, MaxOutputTokens: 32768, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2026-04-02", Source: "builtin"},
		{ID: "deepseek-r1:14b", Name: "DeepSeek R1 14B (Ollama)", Vendor: "Ollama", Protocol: vault.AIProtocolOpenAI, ContextWindow: 65536, MaxInputTokens: 57344, MaxOutputTokens: 8192, SupportsReasoning: true, SupportsTemperature: &t, SupportsTools: true, ReleaseDate: "2025-01-20", Source: "builtin"},
	}
}

// MergedModelCatalog combines built-in defaults with any locally cached online catalog entries.
// Cached online entries override built-in entries with the same normalized ID so newer specs take effect.
func MergedModelCatalog(cached *vault.AIModelCatalogCache) []vault.AIModelCatalogEntry {
	byID := make(map[string]vault.AIModelCatalogEntry, 128)
	order := make([]string, 0, 128)

	add := func(e vault.AIModelCatalogEntry, overwrite bool) {
		key := strings.ToLower(strings.TrimSpace(e.ID))
		if key == "" {
			return
		}
		if _, exists := byID[key]; !exists {
			order = append(order, key)
			byID[key] = e
		} else if overwrite {
			prev := byID[key]
			// Preserve protocol hint from builtin when online source didn't specify one
			if e.Protocol == "" {
				e.Protocol = prev.Protocol
			}
			if e.InterleavedReasoningKey == "" {
				e.InterleavedReasoningKey = prev.InterleavedReasoningKey
			}
			byID[key] = e
		}
	}

	for _, e := range BuiltinModelCatalog() {
		add(e, false)
	}
	if cached != nil {
		for _, e := range cached.Models {
			add(e, true)
		}
	}

	out := make([]vault.AIModelCatalogEntry, 0, len(order))
	for _, k := range order {
		out = append(out, byID[k])
	}
	return out
}

func canonicalModelKey(modelID string) string {
	m := strings.ToLower(strings.TrimSpace(modelID))
	m = strings.TrimPrefix(m, "models/")
	if idx := strings.LastIndex(m, "/"); idx >= 0 && idx < len(m)-1 {
		m = m[idx+1:]
	}
	return m
}

func stripTrailingDateSuffix(modelID string) string {
	// Handles e.g. claude-sonnet-4-5-20250929, gpt-4o-2024-11-20, deepseek-v4-flash-0731
	parts := strings.Split(modelID, "-")
	if len(parts) >= 4 {
		y, mo, d := parts[len(parts)-3], parts[len(parts)-2], parts[len(parts)-1]
		if len(y) == 4 && len(mo) == 2 && len(d) == 2 && isDigits(y) && isDigits(mo) && isDigits(d) {
			return strings.Join(parts[:len(parts)-3], "-")
		}
	}
	if len(parts) >= 2 {
		last := parts[len(parts)-1]
		if (len(last) == 8 || len(last) == 4) && isDigits(last) {
			return strings.Join(parts[:len(parts)-1], "-")
		}
	}
	return modelID
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func inferModelTraits(modelID string, protocol vault.AIProtocol, spec *ModelSpec) {
	m := canonicalModelKey(modelID)

	// OpenAI Chat Completions: o1/o3/o4 & GPT-5/6 require max_completion_tokens instead of max_tokens
	if strings.HasPrefix(m, "o1") || strings.HasPrefix(m, "o3") || strings.HasPrefix(m, "o4") ||
		strings.HasPrefix(m, "gpt-5") || strings.HasPrefix(m, "gpt-6") || strings.HasPrefix(m, "gpt-daybreak") {
		spec.UseMaxCompletionTokens = true
	}

	// Anthropic Adaptive Thinking: Claude 4.6+, 4.7, 4.8, 5, 5.5, Fable 5.x
	if strings.Contains(m, "claude") {
		if strings.Contains(m, "-5") || strings.Contains(m, "fable") ||
			strings.Contains(m, "-4-6") || strings.Contains(m, "-4.6") ||
			strings.Contains(m, "-4-7") || strings.Contains(m, "-4.7") ||
			strings.Contains(m, "-4-8") || strings.Contains(m, "-4.8") ||
			strings.Contains(m, "-4-9") || strings.Contains(m, "-4.9") {
			spec.UseAdaptiveThinking = true
		}
	}

	// Google Gemini 3.x / 4.x / latest aliases use thinkingLevel; Gemini 2.5 uses thinkingBudget
	if strings.Contains(m, "gemini") {
		if strings.Contains(m, "gemini-3") || strings.Contains(m, "gemini-4") ||
			strings.Contains(m, "gemini-5") || strings.Contains(m, "-latest") {
			spec.GeminiUseThinkingLevel = true
		}
	}

	// Interleaved reasoning_content round-trip for DeepSeek / Kimi / GLM / Qwen thinking models
	if spec.InterleavedReasoningKey == "" {
		if strings.Contains(m, "deepseek") || strings.Contains(m, "kimi-k2") || strings.Contains(m, "kimi-k3") ||
			strings.Contains(m, "glm-5") || strings.Contains(m, "glm-4.7") ||
			strings.Contains(m, "qwen3.5") || strings.Contains(m, "qwen3.6") || strings.Contains(m, "qwen3.7") ||
			strings.Contains(m, "qwen3.8") || strings.Contains(m, "qwen4") || strings.Contains(m, "qwq") ||
			strings.Contains(m, "minimax-m2") {
			spec.InterleavedReasoningKey = "reasoning_content"
		}
	}

	// Derive MaxInputTokens cleanly if missing
	if spec.MaxInputTokens <= 0 && spec.ContextWindow > 0 {
		if spec.MaxOutputTokens > 0 && spec.ContextWindow > spec.MaxOutputTokens {
			spec.MaxInputTokens = spec.ContextWindow - spec.MaxOutputTokens
		} else {
			spec.MaxInputTokens = spec.ContextWindow
		}
	}
	if spec.Protocol == "" {
		spec.Protocol = protocol
	}
}

func entryToSpec(e vault.AIModelCatalogEntry, protocol vault.AIProtocol) ModelSpec {
	supportsTemp := true
	if e.SupportsTemperature != nil {
		supportsTemp = *e.SupportsTemperature
	}
	spec := ModelSpec{
		ID:                      e.ID,
		Name:                    e.Name,
		Vendor:                  e.Vendor,
		Protocol:                e.Protocol,
		ContextWindow:           e.ContextWindow,
		MaxInputTokens:          e.MaxInputTokens,
		MaxOutputTokens:         e.MaxOutputTokens,
		SupportsReasoning:       e.SupportsReasoning,
		SupportsTemperature:     supportsTemp,
		SupportsTools:           e.SupportsTools,
		InterleavedReasoningKey: e.InterleavedReasoningKey,
		Source:                  e.Source,
	}
	if spec.Source == "" {
		spec.Source = "builtin"
	}
	inferModelTraits(e.ID, protocol, &spec)
	return spec
}

// LookupModelSpec resolves default token limits and parameter adaptation rules for a model ID
// using the merged online+builtin catalog, falling back to up-to-date family heuristics.
func LookupModelSpec(modelID string, protocol vault.AIProtocol, cached *vault.AIModelCatalogCache) ModelSpec {
	rawLower := strings.ToLower(strings.TrimSpace(modelID))
	canon := canonicalModelKey(modelID)
	stripped := stripTrailingDateSuffix(canon)

	entries := MergedModelCatalog(cached)

	// 1. Exact ID match
	for _, e := range entries {
		if strings.ToLower(strings.TrimSpace(e.ID)) == rawLower {
			return entryToSpec(e, protocol)
		}
	}
	// 2. Canonical (strip vendor prefix like "openai/", "anthropic/", "models/") match
	for _, e := range entries {
		if canonicalModelKey(e.ID) == canon {
			return entryToSpec(e, protocol)
		}
	}
	// 3. Date-stripped match (e.g. claude-sonnet-4-5-20250929 -> claude-sonnet-4-5)
	if stripped != canon {
		for _, e := range entries {
			if canonicalModelKey(e.ID) == stripped {
				return entryToSpec(e, protocol)
			}
		}
	}
	// 4. Longest prefix match (e.g. gpt-6.2-sol-2026-11-17 -> gpt-6.2-sol)
	var bestMatch *vault.AIModelCatalogEntry
	bestLen := 0
	for i := range entries {
		ek := canonicalModelKey(entries[i].ID)
		if len(ek) > bestLen && strings.HasPrefix(canon, ek+"-") {
			bestLen = len(ek)
			bestMatch = &entries[i]
		}
	}
	if bestMatch != nil {
		spec := entryToSpec(*bestMatch, protocol)
		spec.ID = modelID
		inferModelTraits(modelID, protocol, &spec)
		return spec
	}

	// 5. Up-to-date model family heuristic fallback
	spec := ModelSpec{
		ID:                  modelID,
		Protocol:            protocol,
		ContextWindow:       128000,
		MaxOutputTokens:     16384,
		SupportsTemperature: true,
		SupportsTools:       true,
		Source:              "heuristic",
	}
	switch {
	case strings.Contains(canon, "claude"):
		if strings.Contains(canon, "-5") || strings.Contains(canon, "fable") ||
			strings.Contains(canon, "-4-6") || strings.Contains(canon, "-4.6") ||
			strings.Contains(canon, "-4-7") || strings.Contains(canon, "-4.7") ||
			strings.Contains(canon, "-4-8") || strings.Contains(canon, "-4.8") {
			spec.ContextWindow = 1000000
			spec.MaxOutputTokens = 128000
			spec.SupportsReasoning = true
			if strings.Contains(canon, "-5") || strings.Contains(canon, "fable") ||
				strings.Contains(canon, "-4-7") || strings.Contains(canon, "-4-8") {
				spec.SupportsTemperature = false
			}
		} else {
			spec.ContextWindow = 200000
			spec.MaxOutputTokens = 64000
			spec.SupportsReasoning = true
		}
	case strings.Contains(canon, "gemini"):
		spec.ContextWindow = 1048576
		spec.MaxOutputTokens = 65536
		if strings.Contains(canon, "gemini-1.5") || strings.Contains(canon, "gemini-2.0") {
			spec.MaxOutputTokens = 8192
			spec.SupportsReasoning = false
		} else {
			spec.SupportsReasoning = true
		}
	case strings.HasPrefix(canon, "gpt-6") || strings.HasPrefix(canon, "gpt-5.4") ||
		strings.HasPrefix(canon, "gpt-5.5") || strings.HasPrefix(canon, "gpt-5.6"):
		spec.ContextWindow = 1050000
		spec.MaxInputTokens = 922000
		spec.MaxOutputTokens = 128000
		spec.SupportsReasoning = true
		if strings.HasPrefix(canon, "gpt-6.2") || strings.HasPrefix(canon, "gpt-6.1-sol") || strings.Contains(canon, "-pro") {
			spec.SupportsTemperature = false
		}
	case strings.HasPrefix(canon, "gpt-5"):
		spec.ContextWindow = 400000
		spec.MaxInputTokens = 272000
		spec.MaxOutputTokens = 128000
		spec.SupportsReasoning = true
		if canon == "gpt-5" || strings.HasPrefix(canon, "gpt-5-mini") || strings.HasPrefix(canon, "gpt-5-nano") || strings.Contains(canon, "-pro") {
			spec.SupportsTemperature = false
		}
	case strings.HasPrefix(canon, "o1") || strings.HasPrefix(canon, "o3") || strings.HasPrefix(canon, "o4"):
		spec.ContextWindow = 200000
		spec.MaxOutputTokens = 100000
		spec.SupportsReasoning = true
		spec.SupportsTemperature = false
	case strings.Contains(canon, "gpt-4.1"):
		spec.ContextWindow = 1047576
		spec.MaxOutputTokens = 32768
	case strings.Contains(canon, "gpt-4o"):
		spec.ContextWindow = 128000
		spec.MaxOutputTokens = 16384
	case strings.Contains(canon, "deepseek-v4") || strings.Contains(canon, "deepseek-flash"):
		spec.ContextWindow = 1048576
		spec.MaxOutputTokens = 393216
		spec.SupportsReasoning = true
	case strings.Contains(canon, "deepseek"):
		spec.ContextWindow = 131072
		spec.MaxOutputTokens = 65536
		spec.SupportsReasoning = strings.Contains(canon, "r1") || strings.Contains(canon, "reasoner") || strings.Contains(canon, "v3.2")
	case strings.Contains(canon, "qwen4"):
		spec.ContextWindow = 1000000
		spec.MaxOutputTokens = 262144
		spec.SupportsReasoning = true
	case strings.Contains(canon, "qwen3.7") || strings.Contains(canon, "qwen3.8"):
		spec.ContextWindow = 1000000
		spec.MaxOutputTokens = 131072
		spec.SupportsReasoning = true
	case strings.Contains(canon, "qwen3.5") || strings.Contains(canon, "qwen3.6") || strings.Contains(canon, "qwen-plus"):
		spec.ContextWindow = 1000000
		spec.MaxOutputTokens = 65536
		spec.SupportsReasoning = true
	case strings.Contains(canon, "qwen"):
		spec.ContextWindow = 131072
		spec.MaxOutputTokens = 32768
	case strings.Contains(canon, "kimi-k3"):
		spec.ContextWindow = 1048576
		spec.MaxOutputTokens = 131072
		spec.SupportsReasoning = true
		spec.SupportsTemperature = false
	case strings.Contains(canon, "glm-5"):
		spec.ContextWindow = 1000000
		spec.MaxOutputTokens = 131072
		spec.SupportsReasoning = true
	case strings.Contains(canon, "grok-4"):
		spec.ContextWindow = 500000
		spec.MaxOutputTokens = 128000
		spec.SupportsReasoning = true
	case strings.Contains(canon, "llama") || strings.Contains(canon, "mistral") || strings.Contains(canon, "gemma") || strings.Contains(canon, "phi") || strings.Contains(canon, ":"):
		spec.ContextWindow = 65536
		spec.MaxOutputTokens = 16384
	}
	inferModelTraits(modelID, protocol, &spec)
	return spec
}

// SyncPublicModelCatalog fetches the latest public model limits & capabilities from models.dev (primary)
// or OpenRouter (fallback), or a caller-supplied custom catalog URL.
func SyncPublicModelCatalog(ctx context.Context, transport HTTPTransport, customURL string) (*vault.AIModelCatalogCache, error) {
	if transport == nil {
		transport = newDefaultHTTPTransport()
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	headers := map[string]string{
		"Accept":     "application/json",
		"User-Agent": "ServerNeedSafe/ModelCatalogSync",
	}

	type sourceCandidate struct {
		name string
		url  string
	}
	var candidates []sourceCandidate
	if u := strings.TrimSpace(customURL); u != "" {
		candidates = []sourceCandidate{{name: u, url: u}}
	} else {
		candidates = []sourceCandidate{
			{name: "models.dev", url: defaultModelsDevCatalogURL},
			{name: "openrouter", url: defaultOpenRouterCatalogURL},
		}
	}

	var lastErr error
	for _, cand := range candidates {
		status, raw, err := transport.GetJSON(ctx, cand.url, headers)
		if err != nil {
			lastErr = fmt.Errorf("拉取 %s 失败: %w", cand.name, err)
			continue
		}
		if status >= 400 {
			lastErr = fmt.Errorf("拉取 %s 返回 HTTP %d", cand.name, status)
			continue
		}
		models, detectedSource, parseErr := parsePublicCatalogPayload(raw, cand.name)
		if parseErr != nil || len(models) == 0 {
			if parseErr != nil {
				lastErr = fmt.Errorf("解析 %s 数据失败: %w", cand.name, parseErr)
			} else {
				lastErr = fmt.Errorf("%s 返回的模型目录为空", cand.name)
			}
			continue
		}
		now := time.Now().UTC()
		return &vault.AIModelCatalogCache{
			Source:   detectedSource,
			SyncedAt: &now,
			Models:   models,
		}, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("未能连接到任何模型元数据目录源")
	}
	return nil, lastErr
}

func parsePublicCatalogPayload(raw []byte, fallbackSource string) ([]vault.AIModelCatalogEntry, string, error) {
	// Format A: OpenRouter {"data": [{"id": "...", "context_length": ..., "top_provider": {...}}]}
	var orResp struct {
		Data []struct {
			ID                  string   `json:"id"`
			Name                string   `json:"name"`
			ContextLength       int      `json:"context_length"`
			SupportedParameters []string `json:"supported_parameters"`
			TopProvider         struct {
				ContextLength       int `json:"context_length"`
				MaxCompletionTokens int `json:"max_completion_tokens"`
			} `json:"top_provider"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &orResp) == nil && len(orResp.Data) > 0 {
		out := make([]vault.AIModelCatalogEntry, 0, len(orResp.Data))
		for _, item := range orResp.Data {
			id := strings.TrimSpace(item.ID)
			ctxLen := max(item.ContextLength, item.TopProvider.ContextLength)
			if id == "" || ctxLen <= 0 {
				continue
			}
			maxOut := item.TopProvider.MaxCompletionTokens
			maxIn := 0
			if maxOut > 0 && ctxLen > maxOut {
				maxIn = ctxLen - maxOut
			}
			supportsReasoning := slices.Contains(item.SupportedParameters, "reasoning") ||
				slices.Contains(item.SupportedParameters, "reasoning_effort") ||
				slices.Contains(item.SupportedParameters, "include_reasoning")
			supportsTemp := len(item.SupportedParameters) == 0 || slices.Contains(item.SupportedParameters, "temperature")
			supportsTools := len(item.SupportedParameters) == 0 || slices.Contains(item.SupportedParameters, "tools")

			vendor := "OpenRouter"
			if slash := strings.IndexByte(id, '/'); slash > 0 {
				vendor = id[:slash]
			}
			out = append(out, vault.AIModelCatalogEntry{
				ID:                  id,
				Name:                nonEmpty(item.Name, id),
				Vendor:              vendor,
				Protocol:            inferProtocolFromModelID(id),
				ContextWindow:       ctxLen,
				MaxInputTokens:      maxIn,
				MaxOutputTokens:     maxOut,
				SupportsReasoning:   supportsReasoning,
				SupportsTemperature: boolPtr(supportsTemp),
				SupportsTools:       supportsTools,
				Source:              "openrouter",
			})
		}
		return out, "openrouter", nil
	}

	// Format B: models.dev/api.json -> map[providerKey]{name, npm, models: map[modelID]{...}}
	var mdResp map[string]struct {
		Name   string `json:"name"`
		NPM    string `json:"npm"`
		Models map[string]struct {
			Name        string `json:"name"`
			ReleaseDate string `json:"release_date"`
			Reasoning   bool   `json:"reasoning"`
			ToolCall    bool   `json:"tool_call"`
			Temperature *bool  `json:"temperature"`
			Interleaved any    `json:"interleaved"`
			Limit       struct {
				Context int `json:"context"`
				Input   int `json:"input"`
				Output  int `json:"output"`
			} `json:"limit"`
		} `json:"models"`
	}
	if err := json.Unmarshal(raw, &mdResp); err != nil {
		return nil, "", err
	}
	if len(mdResp) == 0 {
		return nil, "", fmt.Errorf("未识别的模型目录 JSON 结构")
	}

	// Prioritize canonical official providers first, followed by popular aggregators so duplicates resolve cleanly.
	priorityProviders := []string{
		"openai", "anthropic", "google", "deepseek",
		"alibaba-cn", "alibaba", "moonshotai", "zhipuai",
		"xai", "minimax", "mistral", "openrouter",
	}
	seenKey := make(map[string]bool, 512)
	out := make([]vault.AIModelCatalogEntry, 0, 512)

	processProvider := func(provKey string) {
		p, ok := mdResp[provKey]
		if !ok || len(p.Models) == 0 {
			return
		}
		// Sort model IDs deterministically
		mids := make([]string, 0, len(p.Models))
		for mid := range p.Models {
			mids = append(mids, mid)
		}
		sort.Strings(mids)

		for _, mid := range mids {
			m := p.Models[mid]
			if m.Limit.Context <= 0 || m.Limit.Output <= 0 {
				continue
			}
			lowerID := strings.ToLower(mid)
			// Skip non-chat models (embeddings, image-only, video, tts, asr)
			if strings.Contains(lowerID, "embedding") || strings.Contains(lowerID, "image") ||
				strings.Contains(lowerID, "video") || strings.Contains(lowerID, "tts") ||
				strings.Contains(lowerID, "asr") || strings.Contains(lowerID, "whisper") ||
				strings.Contains(lowerID, "lyria") {
				continue
			}
			// Keep openrouter entries only if they have a distinct vendor/model ID not already covered
			dedupKey := strings.ToLower(strings.TrimSpace(mid))
			if seenKey[dedupKey] {
				continue
			}
			seenKey[dedupKey] = true

			interleavedField := ""
			if imap, ok := m.Interleaved.(map[string]any); ok {
				if f, ok := imap["field"].(string); ok {
					interleavedField = strings.TrimSpace(f)
				}
			}

			proto := inferProtocolFromProviderAndModel(provKey, mid)
			maxIn := m.Limit.Input
			if maxIn <= 0 && m.Limit.Context > m.Limit.Output {
				maxIn = m.Limit.Context - m.Limit.Output
			}

			var tempPtr *bool
			if m.Temperature != nil {
				v := *m.Temperature
				tempPtr = &v
			}

			out = append(out, vault.AIModelCatalogEntry{
				ID:                      mid,
				Name:                    nonEmpty(m.Name, mid),
				Vendor:                  nonEmpty(p.Name, provKey),
				Protocol:                proto,
				ContextWindow:           m.Limit.Context,
				MaxInputTokens:          maxIn,
				MaxOutputTokens:         m.Limit.Output,
				SupportsReasoning:       m.Reasoning,
				SupportsTemperature:     tempPtr,
				SupportsTools:           m.ToolCall,
				InterleavedReasoningKey: interleavedField,
				ReleaseDate:             m.ReleaseDate,
				Source:                  fallbackSource,
			})
		}
	}

	for _, pk := range priorityProviders {
		processProvider(pk)
	}

	// Sort newest release_date first, then alphabetically
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ReleaseDate != out[j].ReleaseDate {
			return out[i].ReleaseDate > out[j].ReleaseDate
		}
		return out[i].ID < out[j].ID
	})

	return out, fallbackSource, nil
}

func inferProtocolFromProviderAndModel(provKey, modelID string) vault.AIProtocol {
	switch strings.ToLower(provKey) {
	case "anthropic":
		return vault.AIProtocolAnthropic
	case "google":
		return vault.AIProtocolGemini
	case "openai":
		m := canonicalModelKey(modelID)
		if strings.HasPrefix(m, "gpt-5") || strings.HasPrefix(m, "gpt-6") {
			return vault.AIProtocolOpenAIResponses
		}
		return vault.AIProtocolOpenAI
	default:
		return vault.AIProtocolOpenAI
	}
}

func inferProtocolFromModelID(modelID string) vault.AIProtocol {
	m := strings.ToLower(modelID)
	switch {
	case strings.HasPrefix(m, "claude-") || strings.HasPrefix(m, "anthropic/"):
		return vault.AIProtocolAnthropic
	case strings.HasPrefix(m, "gemini-") || strings.HasPrefix(m, "google/gemini"):
		return vault.AIProtocolGemini
	default:
		return vault.AIProtocolOpenAI
	}
}

// FetchProviderModels queries the configured LLM provider's /models endpoint (supporting OpenAI,
// OpenAI Responses, Anthropic, and Google Gemini formats) and enriches each discovered model
// with default context window and input/output limits from the catalog or live API metadata.
func FetchProviderModels(
	ctx context.Context,
	transport HTTPTransport,
	prov vault.AIProviderConfig,
	cached *vault.AIModelCatalogCache,
) ([]vault.AIModelCatalogEntry, error) {
	if transport == nil {
		transport = newDefaultHTTPTransport()
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	proto := vault.NormalizeAIProtocol(prov.Protocol)
	endpoint := resolveModelsEndpoint(prov.BaseURL, proto)
	headers := map[string]string{
		"Accept": "application/json",
	}
	if proto == vault.AIProtocolAnthropic {
		headers["anthropic-version"] = "2023-06-01"
	}
	endpoint = applyAuthAndHeaders(prov, proto, endpoint, headers)

	status, raw, err := transport.GetJSON(ctx, endpoint, headers)
	if err != nil {
		return nil, fmt.Errorf("拉取模型列表失败: %w", sanitizeURLError(err, prov.APIKey))
	}
	if status >= 400 {
		return nil, fmt.Errorf("拉取模型列表返回 HTTP %d: %s", status, extractProviderErrMsg(raw))
	}

	var discovered []vault.AIModelCatalogEntry

	// 1. Gemini format: {"models": [{"name": "models/gemini-...", "displayName": "...", "inputTokenLimit": ..., "outputTokenLimit": ...}]}
	var geminiResp struct {
		Models []struct {
			Name                       string   `json:"name"`
			DisplayName                string   `json:"displayName"`
			InputTokenLimit            int      `json:"inputTokenLimit"`
			OutputTokenLimit           int      `json:"outputTokenLimit"`
			SupportedGenerationMethods []string `json:"supportedGenerationMethods"`
		} `json:"models"`
	}
	if json.Unmarshal(raw, &geminiResp) == nil && len(geminiResp.Models) > 0 {
		for _, gm := range geminiResp.Models {
			id := strings.TrimPrefix(strings.TrimSpace(gm.Name), "models/")
			if id == "" {
				continue
			}
			// Filter to generateContent-capable models when methods are reported
			if len(gm.SupportedGenerationMethods) > 0 &&
				!slices.Contains(gm.SupportedGenerationMethods, "generateContent") &&
				!slices.Contains(gm.SupportedGenerationMethods, "streamGenerateContent") {
				continue
			}
			spec := LookupModelSpec(id, proto, cached)
			ctxWin := spec.ContextWindow
			maxIn := spec.MaxInputTokens
			maxOut := spec.MaxOutputTokens
			if gm.InputTokenLimit > 0 {
				maxIn = gm.InputTokenLimit
				if gm.InputTokenLimit > ctxWin {
					ctxWin = gm.InputTokenLimit
				}
			}
			if gm.OutputTokenLimit > 0 {
				maxOut = gm.OutputTokenLimit
			}
			if ctxWin <= 0 {
				ctxWin = maxIn
			}
			discovered = append(discovered, vault.AIModelCatalogEntry{
				ID:                      id,
				Name:                    nonEmpty(gm.DisplayName, spec.Name),
				Vendor:                  nonEmpty(spec.Vendor, "Google"),
				Protocol:                proto,
				ContextWindow:           ctxWin,
				MaxInputTokens:          maxIn,
				MaxOutputTokens:         maxOut,
				SupportsReasoning:       spec.SupportsReasoning,
				SupportsTemperature:     boolPtr(spec.SupportsTemperature),
				SupportsTools:           true,
				InterleavedReasoningKey: spec.InterleavedReasoningKey,
				Source:                  "provider",
			})
		}
	}

	// 2. OpenAI / Anthropic / OpenRouter / vLLM / Ollama-compat format: {"data": [{"id": "...", ...}]}
	if len(discovered) == 0 {
		var listResp struct {
			Data []struct {
				ID              string `json:"id"`
				DisplayName     string `json:"display_name"`
				Name            string `json:"name"`
				OwnedBy         string `json:"owned_by"`
				ContextLength   int    `json:"context_length"`
				ContextWindow   int    `json:"context_window"`
				MaxModelLen     int    `json:"max_model_len"`
				MaxInputTokens  int    `json:"max_input_tokens"`
				MaxOutputTokens int    `json:"max_output_tokens"`
				TopProvider     struct {
					ContextLength       int `json:"context_length"`
					MaxCompletionTokens int `json:"max_completion_tokens"`
				} `json:"top_provider"`
			} `json:"data"`
		}
		if json.Unmarshal(raw, &listResp) == nil && len(listResp.Data) > 0 {
			for _, item := range listResp.Data {
				id := strings.TrimSpace(item.ID)
				if id == "" {
					continue
				}
				spec := LookupModelSpec(id, proto, cached)
				ctxWin := spec.ContextWindow
				for _, cand := range []int{item.ContextWindow, item.ContextLength, item.MaxModelLen, item.TopProvider.ContextLength} {
					if cand > 0 {
						ctxWin = cand
						break
					}
				}
				maxOut := spec.MaxOutputTokens
				for _, cand := range []int{item.MaxOutputTokens, item.TopProvider.MaxCompletionTokens} {
					if cand > 0 {
						maxOut = cand
						break
					}
				}
				maxIn := spec.MaxInputTokens
				if item.MaxInputTokens > 0 {
					maxIn = item.MaxInputTokens
				} else if ctxWin > 0 && maxOut > 0 && ctxWin > maxOut {
					maxIn = ctxWin - maxOut
				}

				discovered = append(discovered, vault.AIModelCatalogEntry{
					ID:                      id,
					Name:                    nonEmpty(nonEmpty(item.DisplayName, item.Name), spec.Name),
					Vendor:                  nonEmpty(spec.Vendor, item.OwnedBy),
					Protocol:                proto,
					ContextWindow:           ctxWin,
					MaxInputTokens:          maxIn,
					MaxOutputTokens:         maxOut,
					SupportsReasoning:       spec.SupportsReasoning,
					SupportsTemperature:     boolPtr(spec.SupportsTemperature),
					SupportsTools:           true,
					InterleavedReasoningKey: spec.InterleavedReasoningKey,
					Source:                  "provider",
				})
			}
		}
	}

	// 3. Native Ollama /api/tags fallback if someone pointed directly at Ollama root
	if len(discovered) == 0 {
		var ollamaResp struct {
			Models []struct {
				Name  string `json:"name"`
				Model string `json:"model"`
			} `json:"models"`
		}
		if json.Unmarshal(raw, &ollamaResp) == nil && len(ollamaResp.Models) > 0 {
			for _, om := range ollamaResp.Models {
				id := nonEmpty(strings.TrimSpace(om.Model), strings.TrimSpace(om.Name))
				if id == "" {
					continue
				}
				spec := LookupModelSpec(id, proto, cached)
				discovered = append(discovered, vault.AIModelCatalogEntry{
					ID:                  id,
					Name:                id,
					Vendor:              "Ollama",
					Protocol:            proto,
					ContextWindow:       spec.ContextWindow,
					MaxInputTokens:      spec.MaxInputTokens,
					MaxOutputTokens:     spec.MaxOutputTokens,
					SupportsReasoning:   spec.SupportsReasoning,
					SupportsTemperature: boolPtr(spec.SupportsTemperature),
					SupportsTools:       true,
					Source:              "provider",
				})
			}
		}
	}

	if len(discovered) == 0 {
		return nil, fmt.Errorf("接口返回成功但未解析到任何可用模型（可能该网关未开放 /models 列表接口，请手动填写模型 ID）")
	}

	// Deduplicate & sort cleanly
	seen := make(map[string]bool, len(discovered))
	unique := make([]vault.AIModelCatalogEntry, 0, len(discovered))
	for _, m := range discovered {
		k := strings.ToLower(m.ID)
		if seen[k] {
			continue
		}
		seen[k] = true
		unique = append(unique, m)
	}
	sort.SliceStable(unique, func(i, j int) bool {
		return unique[i].ID < unique[j].ID
	})
	return unique, nil
}
