package updater

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// MirrorNode describes either official GitHub direct access or a China GitHub acceleration proxy.
type MirrorNode struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Prefix      string `json:"prefix"` // Empty string for official direct GitHub
	Region      string `json:"region"` // "global" or "cn"
	SupportsAPI bool   `json:"supports_api,omitempty"`
	IsCustom    bool   `json:"is_custom,omitempty"`
}

// MirrorProbeResult records a live reachability & latency measurement for a MirrorNode.
type MirrorProbeResult struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Prefix    string    `json:"prefix"`
	Region    string    `json:"region"`
	IsCustom  bool      `json:"is_custom,omitempty"`
	Reachable bool      `json:"reachable"`
	LatencyMs int64     `json:"latency_ms"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// DefaultBuiltinMirrors returns official GitHub plus curated HTTPS China GitHub release proxies.
func DefaultBuiltinMirrors() []MirrorNode {
	return []MirrorNode{
		{
			ID:          "direct",
			Name:        "GitHub 官方直连",
			Prefix:      "",
			Region:      "global",
			SupportsAPI: true,
		},
		{
			ID:     "gh-proxy",
			Name:   "GH-Proxy 国内加速",
			Prefix: "https://gh-proxy.com/",
			Region: "cn",
		},
		{
			ID:     "ghfast",
			Name:   "GHFast 国内加速",
			Prefix: "https://ghfast.top/",
			Region: "cn",
		},
		{
			ID:     "hk-gh-proxy",
			Name:   "GH-Proxy 香港线路",
			Prefix: "https://hk.gh-proxy.com/",
			Region: "cn",
		},
		{
			ID:     "ghproxy-net",
			Name:   "GHProxy.net 国内加速",
			Prefix: "https://ghproxy.net/",
			Region: "cn",
		},
		{
			ID:     "gh-llkk",
			Name:   "LLKK 国内加速",
			Prefix: "https://gh.llkk.cc/",
			Region: "cn",
		},
	}
}

// ValidateCustomMirrorURL validates and normalizes a user-supplied GitHub acceleration mirror prefix.
func ValidateCustomMirrorURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	if strings.ContainsAny(trimmed, " \t\r\n") {
		return "", errors.New("自定义镜像地址不能包含空白字符")
	}
	probeTarget := strings.ReplaceAll(trimmed, "{url}", "https://github.com/test/repo")
	u, err := url.Parse(probeTarget)
	if err != nil || u.Host == "" {
		return "", errors.New("自定义镜像地址格式无效，请填写完整的 https:// 前缀")
	}
	if u.User != nil {
		return "", errors.New("自定义镜像地址不允许包含明文凭据")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" {
		if scheme == "http" && isLoopbackHost(u.Hostname()) {
			// Allow local loopback HTTP proxies for development/testing or local corporate proxy gateways.
		} else {
			return "", errors.New("出于传输安全要求，自定义加速镜像必须使用 https:// 协议")
		}
	}
	if !strings.Contains(trimmed, "{url}") && !strings.HasSuffix(trimmed, "/") {
		trimmed += "/"
	}
	return trimmed, nil
}

func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// BuildMirroredURL constructs the effective fetch URL for a github.com URL using the given mirror node.
func BuildMirroredURL(node MirrorNode, githubURL string) string {
	if strings.TrimSpace(node.Prefix) == "" {
		return githubURL
	}
	if strings.Contains(node.Prefix, "{url}") {
		return strings.ReplaceAll(node.Prefix, "{url}", githubURL)
	}
	return strings.TrimRight(node.Prefix, "/") + "/" + strings.TrimLeft(githubURL, "/")
}

// MirrorHostKey returns a normalized host key used to distinguish independent mirror origins.
func MirrorHostKey(node MirrorNode) string {
	if strings.TrimSpace(node.Prefix) == "" {
		return "github.com"
	}
	probe := strings.ReplaceAll(node.Prefix, "{url}", "https://github.com/")
	u, err := url.Parse(probe)
	if err != nil || u.Host == "" {
		return strings.ToLower(strings.TrimSpace(node.Prefix))
	}
	return strings.ToLower(u.Host)
}

// ResolveCandidateMirrors returns the candidate mirror pool according to the user's mirror_mode.
func ResolveCandidateMirrors(settings vault.UpdateSettings, builtin []MirrorNode) []MirrorNode {
	if len(builtin) == 0 {
		builtin = DefaultBuiltinMirrors()
	}
	customPrefix, _ := ValidateCustomMirrorURL(settings.CustomMirrorURL)

	var directNode *MirrorNode
	for i := range builtin {
		if builtin[i].Prefix == "" {
			cp := builtin[i]
			directNode = &cp
			break
		}
	}
	if directNode == nil {
		directNode = &MirrorNode{
			ID:          "direct",
			Name:        "GitHub 官方直连",
			Prefix:      "",
			Region:      "global",
			SupportsAPI: true,
		}
	}

	switch settings.MirrorMode {
	case "direct":
		return []MirrorNode{*directNode}
	case "custom":
		if customPrefix != "" {
			// Reuse builtin name if the user picked one of the presets.
			for _, m := range builtin {
				if m.Prefix != "" && strings.EqualFold(strings.TrimRight(m.Prefix, "/"), strings.TrimRight(customPrefix, "/")) {
					cp := m
					cp.IsCustom = true
					return []MirrorNode{cp}
				}
			}
			return []MirrorNode{
				{
					ID:       "custom",
					Name:     fmt.Sprintf("自定义加速 (%s)", MirrorHostKey(MirrorNode{Prefix: customPrefix})),
					Prefix:   customPrefix,
					Region:   "cn",
					IsCustom: true,
				},
			}
		}
		// If custom mode is selected without URL, fall through to auto pool.
	}

	// Auto mode: include custom mirror first if specified, then all built-ins (deduplicated).
	var out []MirrorNode
	seen := make(map[string]struct{})
	addUnique := func(n MirrorNode) {
		key := strings.ToLower(strings.TrimRight(n.Prefix, "/"))
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, n)
	}

	if customPrefix != "" {
		addUnique(MirrorNode{
			ID:       "custom",
			Name:     fmt.Sprintf("自定义加速 (%s)", MirrorHostKey(MirrorNode{Prefix: customPrefix})),
			Prefix:   customPrefix,
			Region:   "cn",
			IsCustom: true,
		})
	}
	for _, m := range builtin {
		addUnique(m)
	}
	return out
}

// ProbeMirrors concurrently probes all candidate mirrors against <githubBase>/<repo>/releases.atom
// to verify authentic GitHub proxy connectivity and measure end-to-end latency.
func ProbeMirrors(
	ctx context.Context,
	client *http.Client,
	githubBaseURL string,
	repoSlug string,
	candidates []MirrorNode,
) []MirrorProbeResult {
	if len(candidates) == 0 {
		return nil
	}
	if client == nil {
		client = newHTTPClient(6 * time.Second)
	}
	atomTarget := strings.TrimRight(githubBaseURL, "/") + "/" + strings.Trim(repoSlug, "/") + "/releases.atom"

	results := make([]MirrorProbeResult, len(candidates))
	var wg sync.WaitGroup
	for i, node := range candidates {
		wg.Add(1)
		go func(idx int, m MirrorNode) {
			defer wg.Done()
			results[idx] = probeSingleMirror(ctx, client, m, atomTarget)
		}(i, node)
	}
	wg.Wait()

	sortProbeResults(results)
	return results
}

func probeSingleMirror(ctx context.Context, client *http.Client, node MirrorNode, atomTarget string) MirrorProbeResult {
	res := MirrorProbeResult{
		ID:        node.ID,
		Name:      node.Name,
		Prefix:    node.Prefix,
		Region:    node.Region,
		IsCustom:  node.IsCustom,
		CheckedAt: time.Now().UTC(),
	}

	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	fetchURL := BuildMirroredURL(node, atomTarget)
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, fetchURL, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("User-Agent", updaterUserAgent)
	req.Header.Set("Accept", "application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.5")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		res.LatencyMs = time.Since(start).Milliseconds()
		res.Error = summarizeNetErr(err)
		return res
	}
	defer resp.Body.Close()

	sample, readErr := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	res.LatencyMs = time.Since(start).Milliseconds()
	if res.LatencyMs <= 0 {
		res.LatencyMs = 1
	}

	if resp.StatusCode != http.StatusOK {
		res.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return res
	}
	if readErr != nil && len(sample) == 0 {
		res.Error = summarizeNetErr(readErr)
		return res
	}
	bodyLower := strings.ToLower(string(sample))
	if !strings.Contains(bodyLower, "<feed") {
		res.Error = "返回内容非有效 GitHub Release Feed（可能被拦截或镜像失效）"
		return res
	}
	res.Reachable = true
	return res
}

// sortProbeResults orders reachable routes by latency ascending, giving official direct GitHub
// a small 80ms tie-breaker when both direct and mirrors are similarly fast.
func sortProbeResults(results []MirrorProbeResult) {
	effectiveScore := func(r MirrorProbeResult) int64 {
		if !r.Reachable {
			return 1<<62 - 1
		}
		score := r.LatencyMs
		if r.Prefix == "" && score > 80 {
			score -= 80
		} else if r.Prefix == "" {
			score = 0
		}
		return score
	}
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Reachable != results[j].Reachable {
			return results[i].Reachable
		}
		return effectiveScore(results[i]) < effectiveScore(results[j])
	})
}

func summarizeNetErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(low, "timeout") || strings.Contains(low, "deadline exceeded"):
		return "连接超时"
	case strings.Contains(low, "connection refused"):
		return "连接被拒绝"
	case strings.Contains(low, "no such host"):
		return "DNS 解析失败"
	case strings.Contains(low, "tls") || strings.Contains(low, "x509"):
		return "TLS 证书握手失败"
	case strings.Contains(low, "eof") || strings.Contains(low, "reset by peer"):
		return "连接被重置"
	default:
		if len(msg) > 96 {
			return msg[:96] + "..."
		}
		return msg
	}
}
