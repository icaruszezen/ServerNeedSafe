package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const (
	// CurrentPersistenceVersion tracks the canonical schema version for persistence fingerprints.
	// Legacy version 0 hashed raw `ls -la` + `cat` output (noisy on parent directory mtime updates).
	// Version 2 hashes sorted structured per-item fingerprints ("mode|uid:gid|sha256" or "symlink->target").
	CurrentPersistenceVersion = 2

	// MaxPersistenceDriftDetails limits how many individual drift entries are listed verbatim
	// before appending a compact summary truncation line.
	MaxPersistenceDriftDetails = 10
)

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// NormalizePersistencePath cleans and validates an absolute persistence path.
// Rejects relative paths, empty strings, "." and "..".
func NormalizePersistencePath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || !strings.HasPrefix(trimmed, "/") {
		return ""
	}
	cleaned := path.Clean(trimmed)
	if cleaned == "" || cleaned == "/" || cleaned == "." || cleaned == ".." {
		return ""
	}
	return cleaned
}

// IsIgnoredPersistencePath returns true for dynamic or non-entry paths that should never
// participate in persistence fingerprints (such as ".", "..", or snapd auto-refresh snap-*.mount units).
func IsIgnoredPersistencePath(raw string) bool {
	cleaned := NormalizePersistencePath(raw)
	if cleaned == "" {
		return true
	}
	base := path.Base(cleaned)
	if base == "" || base == "." || base == ".." {
		return true
	}
	// Ignore snapd auto-refresh dynamic squashfs mount units (both in /etc/systemd/system/
	// and symlinked inside *.wants/ / *.requires/).
	if strings.HasPrefix(base, "snap-") && strings.HasSuffix(base, ".mount") {
		return true
	}
	return false
}

// NormalizePersistenceMode normalizes numeric octal modes ("0644" -> "644") and
// POSIX ls symbolic modes ("-rw-r--r--" / "-rw-r--r--." -> "644") into canonical octal strings.
func NormalizePersistenceMode(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		allOctal := true
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '7' {
				allOctal = false
				break
			}
		}
		if allOctal {
			if v, err := strconv.ParseUint(s, 8, 32); err == nil {
				return fmt.Sprintf("%o", v)
			}
		}
	}
	if oct, ok := parseSymbolicModeToOctal(s); ok {
		return oct
	}
	return s
}

func parseSymbolicModeToOctal(sym string) (string, bool) {
	// Strip optional SELinux/ACL/xattr suffix characters ('.', '+', '@') emitted by ls -nd.
	trimmed := strings.TrimRight(sym, ".+@")
	if len(trimmed) != 10 {
		return "", false
	}
	var perm uint32
	// Owner rwx/sS
	switch trimmed[1] {
	case 'r':
		perm |= 0o400
	case '-':
	default:
		return "", false
	}
	switch trimmed[2] {
	case 'w':
		perm |= 0o200
	case '-':
	default:
		return "", false
	}
	switch trimmed[3] {
	case 'x':
		perm |= 0o100
	case 's':
		perm |= 0o4100
	case 'S':
		perm |= 0o4000
	case '-':
	default:
		return "", false
	}
	// Group rwx/sS
	switch trimmed[4] {
	case 'r':
		perm |= 0o040
	case '-':
	default:
		return "", false
	}
	switch trimmed[5] {
	case 'w':
		perm |= 0o020
	case '-':
	default:
		return "", false
	}
	switch trimmed[6] {
	case 'x':
		perm |= 0o010
	case 's':
		perm |= 0o2010
	case 'S':
		perm |= 0o2000
	case '-':
	default:
		return "", false
	}
	// Other rwx/tT
	switch trimmed[7] {
	case 'r':
		perm |= 0o004
	case '-':
	default:
		return "", false
	}
	switch trimmed[8] {
	case 'w':
		perm |= 0o002
	case '-':
	default:
		return "", false
	}
	switch trimmed[9] {
	case 'x':
		perm |= 0o001
	case 't':
		perm |= 0o1001
	case 'T':
		perm |= 0o1000
	case '-':
	default:
		return "", false
	}
	return fmt.Sprintf("%o", perm), true
}

// NormalizePersistenceValue canonicalizes a persistence fingerprint value:
//   - "symlink->target" for symlinks
//   - "mode|uid:gid|sha256" for regular files
func NormalizePersistenceValue(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, "symlink->") {
		return "symlink->" + strings.TrimSpace(strings.TrimPrefix(v, "symlink->"))
	}
	parts := strings.SplitN(v, "|", 3)
	if len(parts) == 3 {
		mode := NormalizePersistenceMode(parts[0])
		ug := strings.TrimSpace(parts[1])
		digest := strings.ToLower(strings.TrimSpace(parts[2]))
		return mode + "|" + ug + "|" + digest
	}
	return v
}

// NormalizePersistenceItems cleans paths and values and filters out ignored dynamic paths.
func NormalizePersistenceItems(raw map[string]string) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		cleanPath := NormalizePersistencePath(k)
		if cleanPath == "" || IsIgnoredPersistencePath(cleanPath) {
			continue
		}
		cleanVal := NormalizePersistenceValue(v)
		if cleanVal == "" {
			continue
		}
		out[cleanPath] = cleanVal
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ComputePersistenceHash deterministically hashes the sorted canonical persistence inventory
// in byte-lexicographical (LC_ALL=C) order. Always returns a non-empty 24-hex digest even for empty maps.
func ComputePersistenceHash(items map[string]string) string {
	norm := NormalizePersistenceItems(items)
	keys := make([]string, 0, len(norm))
	for k := range norm {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("v2\n")
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('\t')
		b.WriteString(norm[k])
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])[:24]
}

// DiffPersistenceItems computes deterministic human-readable persistence drift descriptions
// between a baseline item map and the current collected item map.
func DiffPersistenceItems(baseItems, curItems map[string]string, maxItems int) []string {
	if maxItems <= 0 {
		maxItems = MaxPersistenceDriftDetails
	}
	baseNorm := NormalizePersistenceItems(baseItems)
	curNorm := NormalizePersistenceItems(curItems)

	var added, modified, deleted []string
	for p := range curNorm {
		if _, ok := baseNorm[p]; !ok {
			added = append(added, p)
		}
	}
	for p, baseVal := range baseNorm {
		curVal, ok := curNorm[p]
		if !ok {
			deleted = append(deleted, p)
		} else if curVal != baseVal {
			modified = append(modified, p)
		}
	}

	sort.Strings(added)
	sort.Strings(modified)
	sort.Strings(deleted)

	all := make([]string, 0, len(added)+len(modified)+len(deleted))
	for _, p := range added {
		all = append(all, "新增: "+p)
	}
	for _, p := range modified {
		all = append(all, formatModifiedPersistenceDrift(p, baseNorm[p], curNorm[p]))
	}
	for _, p := range deleted {
		all = append(all, "删除: "+p)
	}
	if len(all) == 0 {
		return nil
	}
	if len(all) > maxItems {
		out := make([]string, 0, maxItems+1)
		out = append(out, slices.Clone(all[:maxItems])...)
		out = append(out, fmt.Sprintf("...等共 %d 项变更", len(all)))
		return out
	}
	return all
}

// CountPersistenceDrifts returns the true number of drifted persistence items represented by drifts,
// accounting for any summary truncation suffix ("...等共 N 项变更").
func CountPersistenceDrifts(drifts []string) int {
	if len(drifts) == 0 {
		return 0
	}
	last := drifts[len(drifts)-1]
	if strings.HasPrefix(last, "...等共 ") && strings.HasSuffix(last, " 项变更") {
		numStr := strings.TrimSuffix(strings.TrimPrefix(last, "...等共 "), " 项变更")
		if n, err := strconv.Atoi(strings.TrimSpace(numStr)); err == nil && n > 0 {
			return n
		}
	}
	return len(drifts)
}

func formatModifiedPersistenceDrift(p, oldVal, newVal string) string {
	oldSym := strings.HasPrefix(oldVal, "symlink->")
	newSym := strings.HasPrefix(newVal, "symlink->")
	if oldSym && newSym {
		return fmt.Sprintf("修改: %s (软链 -> %s)", p, strings.TrimPrefix(newVal, "symlink->"))
	}
	if oldSym != newSym {
		return fmt.Sprintf("修改: %s (类型变更)", p)
	}
	oldParts := strings.SplitN(oldVal, "|", 3)
	newParts := strings.SplitN(newVal, "|", 3)
	if len(oldParts) == 3 && len(newParts) == 3 && oldParts[2] == newParts[2] {
		return fmt.Sprintf("修改: %s (权限/属主变更)", p)
	}
	return "修改: " + p
}
