package version

import (
	"fmt"
	"runtime"
	"strings"
)

const (
	RepoOwner = "icaruszezen"
	RepoName  = "ServerNeedSafe"
	RepoSlug  = RepoOwner + "/" + RepoName
	GHCRImage = "ghcr.io/icaruszezen/serverneedsafe"
)

// Build-time metadata injected via -ldflags.
var (
	Version   = "dev"
	Commit    = ""
	BuildTime = ""
)

// Info describes the running binary's version and build environment.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildTime string `json:"build_time,omitempty"`
	GoVersion string `json:"go_version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	Repo      string `json:"repo"`
	IsDev     bool   `json:"is_dev"`
}

// Current returns the normalized build metadata for this binary.
func Current() Info {
	v := strings.TrimSpace(Version)
	if v == "" {
		v = "dev"
	}
	return Info{
		Version:   v,
		Commit:    strings.TrimSpace(Commit),
		BuildTime: strings.TrimSpace(BuildTime),
		GoVersion: runtime.Version(),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		Repo:      RepoSlug,
		IsDev:     IsDevVersion(v),
	}
}

// IsDevVersion reports whether the given version string represents a local/untagged development build.
func IsDevVersion(v string) bool {
	low := strings.ToLower(strings.TrimSpace(v))
	if low == "" || low == "dev" || low == "unknown" || low == "nightly" {
		return true
	}
	if strings.HasPrefix(low, "dev-") || strings.HasPrefix(low, "dev.") {
		return true
	}
	return false
}

// String formats a concise single-line version banner suitable for `--version`.
func String() string {
	info := Current()
	var parts []string
	parts = append(parts, fmt.Sprintf("ServerNeedSafe %s (%s/%s)", info.Version, info.GOOS, info.GOARCH))
	if info.Commit != "" {
		short := info.Commit
		if len(short) > 12 {
			short = short[:12]
		}
		parts = append(parts, "commit="+short)
	}
	if info.BuildTime != "" {
		parts = append(parts, "built="+info.BuildTime)
	}
	return strings.Join(parts, " ")
}
