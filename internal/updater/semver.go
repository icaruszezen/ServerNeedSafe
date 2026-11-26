package updater

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/icaruszezen/ServerNeedSafe/internal/version"
)

// SemVer represents a parsed Semantic Versioning 2.0.0 tag.
type SemVer struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease []string
	Raw        string
}

// ParseSemVer parses strings such as "v2.3.0", "2.4.1-rc.1+meta", or "v2.4".
func ParseSemVer(raw string) (SemVer, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return SemVer{}, fmt.Errorf("empty version string")
	}
	orig := s
	if strings.HasPrefix(s, "v") || strings.HasPrefix(s, "V") {
		s = s[1:]
	}
	// Strip build metadata (+...)
	if plusIdx := strings.IndexByte(s, '+'); plusIdx >= 0 {
		s = s[:plusIdx]
	}
	var pre []string
	if dashIdx := strings.IndexByte(s, '-'); dashIdx >= 0 {
		preStr := s[dashIdx+1:]
		s = s[:dashIdx]
		if preStr == "" {
			return SemVer{}, fmt.Errorf("invalid prerelease in %q", orig)
		}
		pre = strings.Split(preStr, ".")
	}

	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return SemVer{}, fmt.Errorf("invalid semver core in %q", orig)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 0 {
		return SemVer{}, fmt.Errorf("invalid major version in %q", orig)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil || minor < 0 {
		return SemVer{}, fmt.Errorf("invalid minor version in %q", orig)
	}
	patch := 0
	if len(parts) == 3 {
		patch, err = strconv.Atoi(parts[2])
		if err != nil || patch < 0 {
			return SemVer{}, fmt.Errorf("invalid patch version in %q", orig)
		}
	}

	return SemVer{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: pre,
		Raw:        orig,
	}, nil
}

// IsPrereleaseTag reports whether a tag string represents a SemVer prerelease (e.g. v2.4.0-rc.1).
func IsPrereleaseTag(raw string) bool {
	sv, err := ParseSemVer(raw)
	if err != nil {
		low := strings.ToLower(raw)
		return strings.Contains(low, "-rc") || strings.Contains(low, "-beta") || strings.Contains(low, "-alpha")
	}
	return len(sv.Prerelease) > 0
}

// CompareSemVer compares two semantic versions.
// Returns -1 if a < b, 0 if a == b, +1 if a > b.
func CompareSemVer(a, b string) (int, error) {
	va, err := ParseSemVer(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseSemVer(b)
	if err != nil {
		return 0, err
	}
	if va.Major != vb.Major {
		if va.Major < vb.Major {
			return -1, nil
		}
		return 1, nil
	}
	if va.Minor != vb.Minor {
		if va.Minor < vb.Minor {
			return -1, nil
		}
		return 1, nil
	}
	if va.Patch != vb.Patch {
		if va.Patch < vb.Patch {
			return -1, nil
		}
		return 1, nil
	}

	// Absence of prerelease has higher precedence than presence of prerelease.
	if len(va.Prerelease) == 0 && len(vb.Prerelease) == 0 {
		return 0, nil
	}
	if len(va.Prerelease) == 0 {
		return 1, nil
	}
	if len(vb.Prerelease) == 0 {
		return -1, nil
	}

	minLen := len(va.Prerelease)
	if len(vb.Prerelease) < minLen {
		minLen = len(vb.Prerelease)
	}
	for i := 0; i < minLen; i++ {
		pa, pb := va.Prerelease[i], vb.Prerelease[i]
		if pa == pb {
			continue
		}
		na, errA := strconv.Atoi(pa)
		nb, errB := strconv.Atoi(pb)
		switch {
		case errA == nil && errB == nil:
			if na < nb {
				return -1, nil
			}
			return 1, nil
		case errA == nil && errB != nil:
			// Numeric identifiers always have lower precedence than non-numeric.
			return -1, nil
		case errA != nil && errB == nil:
			return 1, nil
		default:
			if pa < pb {
				return -1, nil
			}
			return 1, nil
		}
	}

	if len(va.Prerelease) < len(vb.Prerelease) {
		return -1, nil
	}
	if len(va.Prerelease) > len(vb.Prerelease) {
		return 1, nil
	}
	return 0, nil
}

// IsNewerVersion returns true iff candidate is strictly newer than current.
// Local development builds ("dev") return false so they are not nagged to self-overwrite.
func IsNewerVersion(candidate, current string) bool {
	if version.IsDevVersion(current) {
		return false
	}
	cmp, err := CompareSemVer(candidate, current)
	if err != nil {
		return false
	}
	return cmp > 0
}
