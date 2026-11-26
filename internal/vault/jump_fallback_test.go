package vault

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func boolPtr(b bool) *bool { return &b }

func TestMultiJumpConfigValidationLegacyCompatAndDeleteCleanup(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	store.SetFlushDebounce(20 * time.Millisecond)

	if err := store.Setup("StrongMasterPass#2026", "127.0.0.1"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	pass := "secret"
	createNode := func(name string, host string, jumpIDs []string, legacyJump string, fbDirect *bool) (*ServerView, error) {
		return store.CreateServer(ServerMutationInput{
			Name:               name,
			Group:              "海外节点",
			Host:               host,
			Port:               22,
			Username:           "root",
			AuthType:           AuthPassword,
			Password:           &pass,
			JumpServerID:       legacyJump,
			JumpServerIDs:      jumpIDs,
			JumpFallbackDirect: fbDirect,
		}, "127.0.0.1")
	}

	outer, err := createNode("Outer-Relay", "10.0.0.1", nil, "", nil)
	if err != nil {
		t.Fatalf("create outer: %v", err)
	}
	j1, err := createNode("Jump-HK", "10.0.0.2", []string{outer.ID}, "", boolPtr(false))
	if err != nil {
		t.Fatalf("create j1: %v", err)
	}
	j2, err := createNode("Jump-SG", "10.0.0.3", []string{outer.ID}, "", boolPtr(false))
	if err != nil {
		t.Fatalf("create j2: %v", err)
	}

	// 1. Legacy single JumpServerID input (JumpServerIDs omitted/nil) remains 100% compatible
	legacyTarget, err := createNode("Legacy-Node", "10.0.1.1", nil, j1.ID, nil)
	if err != nil {
		t.Fatalf("create legacy target: %v", err)
	}
	if legacyTarget.JumpServerID != j1.ID || !slices.Equal(legacyTarget.JumpServerIDs, []string{j1.ID}) || legacyTarget.JumpFallbackDirect {
		t.Fatalf("unexpected legacy target jump view: %+v", legacyTarget)
	}

	// 2. Diamond DAG (target -> [j1, j2], both -> outer) + duplicate deduplication + fallback direct
	target, err := createNode("US-Prod", "10.0.2.1", []string{j1.ID, j2.ID, j1.ID}, "", boolPtr(true))
	if err != nil {
		t.Fatalf("create diamond target: %v", err)
	}
	if target.JumpServerID != j1.ID || !slices.Equal(target.JumpServerIDs, []string{j1.ID, j2.ID}) || !target.JumpFallbackDirect {
		t.Fatalf("unexpected multi-jump target view: %+v", target)
	}

	// 3. Cycle detection on UpdateServer: outer -> target creates outer -> target -> j1 -> outer cycle
	_, err = store.UpdateServer(outer.ID, ServerMutationInput{
		Name:          outer.Name,
		Group:         outer.Group,
		Host:          outer.Host,
		Port:          outer.Port,
		Username:      outer.Username,
		AuthType:      AuthPassword,
		JumpServerIDs: []string{target.ID},
	}, "127.0.0.1")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for jump cycle, got: %v", err)
	}

	// 4. Self-reference blocked
	_, err = store.UpdateServer(j1.ID, ServerMutationInput{
		Name:          j1.Name,
		Group:         j1.Group,
		Host:          j1.Host,
		Port:          j1.Port,
		Username:      j1.Username,
		AuthType:      AuthPassword,
		JumpServerIDs: []string{j1.ID},
	}, "127.0.0.1")
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for self jump, got: %v", err)
	}

	// 5. Non-existent jump node blocked
	_, err = createNode("Bad-Jump-Ref", "10.0.3.1", []string{"non-existent-id"}, "", boolPtr(false))
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for missing jump node, got: %v", err)
	}

	// 6. Deleting j1 shifts j2 to primary on target, while legacyTarget becomes direct
	if err := store.DeleteServer(j1.ID, "127.0.0.1"); err != nil {
		t.Fatalf("DeleteServer j1: %v", err)
	}
	targetSec, err := store.GetServerSecret(target.ID)
	if err != nil {
		t.Fatalf("GetServerSecret target: %v", err)
	}
	if targetSec.JumpServerID != j2.ID || !slices.Equal(targetSec.JumpServerIDs, []string{j2.ID}) || !targetSec.JumpFallbackDirect {
		t.Fatalf("expected j2 promoted after deleting j1, got: %+v", targetSec)
	}
	legacySec, err := store.GetServerSecret(legacyTarget.ID)
	if err != nil {
		t.Fatalf("GetServerSecret legacyTarget: %v", err)
	}
	if legacySec.JumpServerID != "" || len(legacySec.JumpServerIDs) != 0 || legacySec.JumpFallbackDirect {
		t.Fatalf("expected legacyTarget reverted to direct after deleting j1, got: %+v", legacySec)
	}

	// 7. Deleting last remaining jump j2 cleans target to direct and resets JumpFallbackDirect
	if err := store.DeleteServer(j2.ID, "127.0.0.1"); err != nil {
		t.Fatalf("DeleteServer j2: %v", err)
	}
	targetSec, err = store.GetServerSecret(target.ID)
	if err != nil {
		t.Fatalf("GetServerSecret target after j2 delete: %v", err)
	}
	if targetSec.JumpServerID != "" || len(targetSec.JumpServerIDs) != 0 || targetSec.JumpFallbackDirect {
		t.Fatalf("expected target reverted to direct after deleting all jumps, got: %+v", targetSec)
	}
}
