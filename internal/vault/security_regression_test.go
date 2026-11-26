package vault

import (
	"errors"
	"testing"
)

const regressionPass = "RegressionAdmin#2026!Pass"

func newRegressionStore(t *testing.T) (string, *Store) {
	t.Helper()
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Setup(regressionPass, "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return dir, s
}

func TestKDFCeilingRejectsOOMParameters(t *testing.T) {
	cases := []struct {
		name    string
		time    uint32
		mem     uint32
		threads uint8
	}{
		{"memory", 1, MaxAllowedKDFMemoryKiB + 1, 1},
		{"time", MaxAllowedKDFTime + 1, 16 * 1024, 1},
		{"threads", 1, 16 * 1024, MaxAllowedKDFThreads + 1},
		{"zero_time", 0, 16 * 1024, 1},
	}
	for _, tc := range cases {
		if err := checkKDFCeiling(tc.time, tc.mem, tc.threads); !errors.Is(err, ErrCorruptedVault) {
			t.Fatalf("%s: expected ErrCorruptedVault for out-of-bounds KDF params, got %v", tc.name, err)
		}
	}
}

func TestAIProviderStoredKeyNotRepointed(t *testing.T) {
	_, store := newRegressionStore(t)
	key := "sk-regression-secret-key"
	view, _, err := store.UpsertAIProvider(AIProviderMutationInput{
		Name: "prod-llm", Protocol: AIProtocolOpenAI, BaseURL: "https://api.example.com/v1/", APIKey: &key, Model: "m1",
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpsertAIProvider(create): %v", err)
	}
	// Same endpoint (trailing slash / host case only) without re-entering key -> allowed.
	if _, _, err := store.UpsertAIProvider(AIProviderMutationInput{
		ID: view.ID, Name: "prod-llm-renamed", Protocol: AIProtocolOpenAI, BaseURL: "https://API.example.com/v1", Model: "m2",
	}, "127.0.0.1"); err != nil {
		t.Fatalf("same-endpoint update rejected: %v", err)
	}
	// Re-pointing to an attacker endpoint while keeping the stored key -> rejected.
	if _, _, err := store.UpsertAIProvider(AIProviderMutationInput{
		ID: view.ID, Name: "prod-llm", Protocol: AIProtocolOpenAI, BaseURL: "https://attacker.example/v1", Model: "m2",
	}, "127.0.0.1"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput when re-pointing stored key, got %v", err)
	}
	stored, err := store.GetAIProviderSecret(view.ID)
	if err != nil || stored.BaseURL != "https://API.example.com/v1" || stored.APIKey != key {
		t.Fatalf("stored provider changed unexpectedly: %+v err=%v", stored, err)
	}
	// Supplying a new key together with the new endpoint is fine.
	newKey := "sk-new-endpoint-key"
	if _, _, err := store.UpsertAIProvider(AIProviderMutationInput{
		ID: view.ID, Name: "prod-llm", Protocol: AIProtocolOpenAI, BaseURL: "https://other.example/v1", APIKey: &newKey, Model: "m2",
	}, "127.0.0.1"); err != nil {
		t.Fatalf("endpoint change with new key rejected: %v", err)
	}
}
