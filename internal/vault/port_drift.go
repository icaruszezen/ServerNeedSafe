package vault

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// EphemeralUDPPortMin is the lower bound of standard Linux (32768-60999) and
// IANA/macOS/BSD (49152-65535) ephemeral ports used by unconnected client/P2P/STUN/QUIC UDP sockets.
const EphemeralUDPPortMin = 32768

// DefaultPortDriftIgnoreProcesses lists well-known P2P, remote-desktop, mesh-VPN, proxy,
// and OS daemons that routinely bind and rotate dynamic ports at runtime.
// Patterns are matched case-insensitively, support '*' wildcards, and optionally accept
// a "tcp:" or "udp:" protocol prefix so static TCP listeners remain strictly monitored.
func DefaultPortDriftIgnoreProcesses() []string {
	return []string{
		"rustdesk*",
		"hbbs",
		"hbbr",
		"todesk*",
		"anydesk*",
		"teamviewer*",
		"sunlogin*",
		"tailscaled",
		"zerotier*",
		"syncthing",
		"udp:xray*",
		"udp:v2ray*",
		"udp:sing-box*",
		"udp:mihomo*",
		"udp:clash*",
		"udp:hysteria*",
		"udp:syslogd",
		"udp:replicatord",
		"tcp:rapportd",
	}
}

// NormalizeBaseProto folds tcp/tcp6 -> "tcp" and udp/udp6 -> "udp".
func NormalizeBaseProto(proto string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(proto)), "udp") {
		return "udp"
	}
	return "tcp"
}

// ValidatePortDriftProcessPattern validates and canonicalizes a single process ignore pattern
// (e.g. "rustdesk*", "udp:xray*", "tcp:rapportd", "OrbStack Helper").
func ValidatePortDriftProcessPattern(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("%w: 进程匹配规则不能为空", ErrInvalidInput)
	}
	if len(trimmed) > 80 {
		return "", fmt.Errorf("%w: 进程匹配规则过长（最多 80 字符）: %s", ErrInvalidInput, trimmed)
	}

	protoPrefix := ""
	body := trimmed
	low := strings.ToLower(trimmed)
	if strings.HasPrefix(low, "tcp:") {
		protoPrefix = "tcp:"
		body = strings.TrimSpace(trimmed[4:])
	} else if strings.HasPrefix(low, "udp:") {
		protoPrefix = "udp:"
		body = strings.TrimSpace(trimmed[4:])
	}
	if body == "" {
		return "", fmt.Errorf("%w: 进程匹配规则缺少进程名: %s", ErrInvalidInput, trimmed)
	}
	// Disallow pure wildcard "*" or "**" that would silently blind all port drift monitoring.
	if strings.Trim(body, "*") == "" {
		return "", fmt.Errorf("%w: 不允许使用纯通配符 \"%s\" 忽略全部进程", ErrInvalidInput, trimmed)
	}
	for _, ch := range body {
		valid := (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '@' || ch == '+' || ch == '/' || ch == '*' || ch == ' '
		if !valid {
			return "", fmt.Errorf("%w: 进程匹配规则包含不支持的字符: %s", ErrInvalidInput, trimmed)
		}
	}
	return protoPrefix + body, nil
}

// SanitizePortDriftProcessPatterns normalizes and deduplicates a list of process patterns,
// silently skipping invalid legacy/blank entries.
func SanitizePortDriftProcessPatterns(raw []string) []string {
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, item := range raw {
		clean, err := ValidatePortDriftProcessPattern(item)
		if err != nil {
			continue
		}
		key := strings.ToLower(clean)
		if !seen[key] {
			seen[key] = true
			out = append(out, clean)
		}
	}
	return out
}

// ValidatePortDriftProcessPatternsStrict validates every non-empty pattern and returns an error on invalid input.
func ValidatePortDriftProcessPatternsStrict(raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, item := range raw {
		if strings.TrimSpace(item) == "" {
			continue
		}
		clean, err := ValidatePortDriftProcessPattern(item)
		if err != nil {
			return nil, err
		}
		key := strings.ToLower(clean)
		if !seen[key] {
			seen[key] = true
			out = append(out, clean)
		}
	}
	return out, nil
}

// ValidatePortDriftPortSpec validates and canonicalizes a port or port-range rule.
// Supported forms: "5353", "tcp/8080", "udp/5353", "50000-60000", "udp/10000-20000", "tcp/49152-65535".
func ValidatePortDriftPortSpec(raw string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return "", fmt.Errorf("%w: 端口忽略规则不能为空", ErrInvalidInput)
	}
	proto := ""
	portPart := trimmed
	if idx := strings.IndexByte(trimmed, '/'); idx >= 0 {
		proto = strings.TrimSpace(trimmed[:idx])
		portPart = strings.TrimSpace(trimmed[idx+1:])
		if proto != "tcp" && proto != "udp" {
			return "", fmt.Errorf("%w: 端口规则协议仅支持 tcp 或 udp: %s", ErrInvalidInput, raw)
		}
	}

	var startPort, endPort int
	if dash := strings.IndexByte(portPart, '-'); dash >= 0 {
		p1, err1 := strconv.Atoi(strings.TrimSpace(portPart[:dash]))
		p2, err2 := strconv.Atoi(strings.TrimSpace(portPart[dash+1:]))
		if err1 != nil || err2 != nil || p1 < 1 || p2 > 65535 || p1 > p2 {
			return "", fmt.Errorf("%w: 端口范围无效（需满足 1 <= 起始 <= 结束 <= 65535）: %s", ErrInvalidInput, raw)
		}
		startPort, endPort = p1, p2
	} else {
		p, err := strconv.Atoi(portPart)
		if err != nil || p < 1 || p > 65535 {
			return "", fmt.Errorf("%w: 端口号无效（范围 1..65535）: %s", ErrInvalidInput, raw)
		}
		startPort, endPort = p, p
	}

	var canonical string
	if startPort == endPort {
		canonical = strconv.Itoa(startPort)
	} else {
		canonical = fmt.Sprintf("%d-%d", startPort, endPort)
	}
	if proto != "" {
		return proto + "/" + canonical, nil
	}
	return canonical, nil
}

// SanitizePortDriftPortSpecs normalizes and deduplicates port/range rules, skipping invalid entries.
func SanitizePortDriftPortSpecs(raw []string) []string {
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, item := range raw {
		clean, err := ValidatePortDriftPortSpec(item)
		if err != nil {
			continue
		}
		if !seen[clean] {
			seen[clean] = true
			out = append(out, clean)
		}
	}
	return out
}

// ValidatePortDriftPortSpecsStrict validates every non-empty port/range rule and returns an error on invalid input.
func ValidatePortDriftPortSpecsStrict(raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, item := range raw {
		if strings.TrimSpace(item) == "" {
			continue
		}
		clean, err := ValidatePortDriftPortSpec(item)
		if err != nil {
			return nil, err
		}
		if !seen[clean] {
			seen[clean] = true
			out = append(out, clean)
		}
	}
	return out, nil
}

// matchWildcardFold matches str against pattern case-insensitively with '*' matching zero or more runes.
func matchWildcardFold(pattern, str string) bool {
	p := []rune(strings.ToLower(pattern))
	s := []rune(strings.ToLower(str))
	pi, si := 0, 0
	starIdx := -1
	matchIdx := 0
	for si < len(s) {
		if pi < len(p) && p[pi] == s[si] {
			pi++
			si++
		} else if pi < len(p) && p[pi] == '*' {
			starIdx = pi
			matchIdx = si
			pi++
		} else if starIdx != -1 {
			pi = starIdx + 1
			matchIdx++
			si = matchIdx
		} else {
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// MatchPortDriftProcessPattern checks whether a listening socket's protocol & process name match pattern.
// Unnamed processes (empty string) never match process patterns.
func MatchPortDriftProcessPattern(pattern, proto, process string) bool {
	proc := strings.TrimSpace(process)
	if proc == "" {
		return false
	}
	pat := strings.TrimSpace(pattern)
	if pat == "" {
		return false
	}
	baseProto := NormalizeBaseProto(proto)
	low := strings.ToLower(pat)
	if strings.HasPrefix(low, "tcp:") {
		if baseProto != "tcp" {
			return false
		}
		pat = strings.TrimSpace(pat[4:])
	} else if strings.HasPrefix(low, "udp:") {
		if baseProto != "udp" {
			return false
		}
		pat = strings.TrimSpace(pat[4:])
	}
	if pat == "" || strings.Trim(pat, "*") == "" {
		return false
	}
	return matchWildcardFold(pat, proc)
}

// MatchPortDriftPortSpec checks whether a listening socket's protocol & port match a port/range spec.
func MatchPortDriftPortSpec(spec, proto string, port int) bool {
	if port <= 0 || port > 65535 {
		return false
	}
	clean, err := ValidatePortDriftPortSpec(spec)
	if err != nil {
		return false
	}
	baseProto := NormalizeBaseProto(proto)
	portPart := clean
	if idx := strings.IndexByte(clean, '/'); idx >= 0 {
		if clean[:idx] != baseProto {
			return false
		}
		portPart = clean[idx+1:]
	}
	if dash := strings.IndexByte(portPart, '-'); dash >= 0 {
		p1, _ := strconv.Atoi(portPart[:dash])
		p2, _ := strconv.Atoi(portPart[dash+1:])
		return port >= p1 && port <= p2
	}
	p, _ := strconv.Atoi(portPart)
	return port == p
}

// EvaluatePortDriftIgnore determines whether an exposed listening socket should be exempted
// from port_drift baseline tracking & alerting, along with a human-readable explanation.
func EvaluatePortDriftIgnore(lp ListeningPortStat, settings MonitorSettings, srv ServerConfig) (bool, string) {
	if !lp.PublicExposed || lp.Port <= 0 {
		return false, ""
	}
	baseProto := NormalizeBaseProto(lp.Proto)

	for _, pat := range srv.IgnoredPortDriftProcesses {
		if MatchPortDriftProcessPattern(pat, lp.Proto, lp.Process) {
			return true, fmt.Sprintf("本机进程白名单: %s", pat)
		}
	}
	for _, spec := range srv.IgnoredPortDriftPorts {
		if MatchPortDriftPortSpec(spec, lp.Proto, lp.Port) {
			return true, fmt.Sprintf("本机端口白名单: %s", spec)
		}
	}
	for _, pat := range settings.PortDriftIgnoreProcesses {
		if MatchPortDriftProcessPattern(pat, lp.Proto, lp.Process) {
			return true, fmt.Sprintf("全局进程白名单: %s", pat)
		}
	}
	for _, spec := range settings.PortDriftIgnorePorts {
		if MatchPortDriftPortSpec(spec, lp.Proto, lp.Port) {
			return true, fmt.Sprintf("全局端口白名单: %s", spec)
		}
	}
	if settings.PortDriftIgnoreEphemeralUDP && baseProto == "udp" && lp.Port >= EphemeralUDPPortMin {
		return true, fmt.Sprintf("临时高端口 UDP (≥%d)", EphemeralUDPPortMin)
	}
	return false, ""
}

// AnnotateListeningPorts marks DriftIgnored & IgnoreReason on every socket in-place.
func AnnotateListeningPorts(ports []ListeningPortStat, settings MonitorSettings, srv ServerConfig) {
	for i := range ports {
		ports[i].DriftIgnored = false
		ports[i].IgnoreReason = ""
		if !ports[i].PublicExposed || ports[i].Port <= 0 {
			continue
		}
		if ignored, reason := EvaluatePortDriftIgnore(ports[i], settings, srv); ignored {
			ports[i].DriftIgnored = true
			ports[i].IgnoreReason = reason
		}
	}
}

// ExtractEligiblePublicPortKeys returns sorted unique "proto/port" keys for exposed ports
// that are NOT exempted from port drift monitoring.
func ExtractEligiblePublicPortKeys(ports []ListeningPortStat) []string {
	seen := make(map[string]struct{})
	for _, p := range ports {
		if !p.PublicExposed || p.Port <= 0 || p.DriftIgnored {
			continue
		}
		key := fmt.Sprintf("%s/%d", NormalizeBaseProto(p.Proto), p.Port)
		seen[key] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func exposureScopePriority(scope string) int {
	switch scope {
	case "public_ip":
		return 3
	case "wildcard":
		return 2
	case "private_ip":
		return 1
	default:
		return 0
	}
}

// ComputeDriftedPorts returns deduplicated exposed, non-ignored ports not present in baselineKeys.
// When dual-stack sockets (e.g. tcp + tcp6 on the same port) exist, it preserves the richest entry
// (preferring a non-empty Process name and higher exposure scope specificity).
func ComputeDriftedPorts(ports []ListeningPortStat, baselineKeys []string) []ListeningPortStat {
	baseSet := make(map[string]bool, len(baselineKeys))
	for _, k := range baselineKeys {
		baseSet[k] = true
	}
	idxByKey := make(map[string]int)
	var drifted []ListeningPortStat
	for _, lp := range ports {
		if !lp.PublicExposed || lp.Port <= 0 || lp.DriftIgnored {
			continue
		}
		key := fmt.Sprintf("%s/%d", NormalizeBaseProto(lp.Proto), lp.Port)
		if baseSet[key] {
			continue
		}
		if existingIdx, exists := idxByKey[key]; exists {
			cur := drifted[existingIdx]
			preferNew := (cur.Process == "" && lp.Process != "") ||
				(exposureScopePriority(lp.ExposureScope) > exposureScopePriority(cur.ExposureScope))
			if preferNew {
				drifted[existingIdx] = lp
			}
			continue
		}
		idxByKey[key] = len(drifted)
		drifted = append(drifted, lp)
	}
	return drifted
}

// BuildPortDriftCandidateBreach formats the standardized port_drift CandidateBreach payload.
func BuildPortDriftCandidateBreach(srv ServerConfig, rule MonitorAlertRule, driftedPorts []ListeningPortStat, consecutiveReq int) CandidateBreach {
	desc := make([]string, 0, len(driftedPorts))
	for _, dp := range driftedPorts {
		proc := dp.Process
		if proc == "" {
			proc = "未知进程"
		}
		scopeHint := dp.BindAddr
		if dp.ExposureScope == "public_ip" {
			scopeHint = dp.BindAddr + "/公网IP"
		}
		desc = append(desc, fmt.Sprintf("%s/%d@%s (%s)", dp.Proto, dp.Port, scopeHint, proc))
	}
	return CandidateBreach{
		DedupKey:       fmt.Sprintf("%s|port_drift|", srv.ID),
		RuleKind:       "port_drift",
		RuleName:       rule.Name,
		Severity:       SeverityWarning,
		Title:          fmt.Sprintf("[%s] 发现 %d 个新暴露监听端口", srv.Name, len(driftedPorts)),
		Detail:         fmt.Sprintf("相较安全基线新增对外监听端口: %s（若属固定服务可采纳基线，若属动态端口应用可一键加入忽略白名单）", strings.Join(desc, ", ")),
		MetricText:     fmt.Sprintf("+%d 端口", len(driftedPorts)),
		ThresholdText:  "匹配端口基线",
		ConsecutiveReq: max(1, consecutiveReq),
	}
}

// PortDriftIgnoreMutation describes an add/remove request for a global or per-server port drift ignore rule.
type PortDriftIgnoreMutation struct {
	ServerID string `json:"server_id"`
	Scope    string `json:"scope"`  // "server" (default) or "global"
	Action   string `json:"action"` // "add" (default) or "remove"
	Process  string `json:"process,omitempty"`
	Port     string `json:"port,omitempty"`
}

// PortDriftIgnoreResult returns the updated allowlists and immediate alert reconciliation summary.
type PortDriftIgnoreResult struct {
	Scope                 string   `json:"scope"`
	Action                string   `json:"action"`
	ServerID              string   `json:"server_id,omitempty"`
	AppliedRule           string   `json:"applied_rule"`
	RuleType              string   `json:"rule_type"` // "process" or "port"
	ResolvedAlerts        int      `json:"resolved_alerts"`
	GlobalIgnoreProcesses []string `json:"global_ignore_processes"`
	GlobalIgnorePorts     []string `json:"global_ignore_ports"`
	ServerIgnoreProcesses []string `json:"server_ignore_processes,omitempty"`
	ServerIgnorePorts     []string `json:"server_ignore_ports,omitempty"`
}

func cloneMonitorSettings(in MonitorSettings) MonitorSettings {
	cp := in
	if in.PortDriftIgnoreProcesses != nil {
		cp.PortDriftIgnoreProcesses = slices.Clone(in.PortDriftIgnoreProcesses)
	} else {
		cp.PortDriftIgnoreProcesses = []string{}
	}
	if in.PortDriftIgnorePorts != nil {
		cp.PortDriftIgnorePorts = slices.Clone(in.PortDriftIgnorePorts)
	} else {
		cp.PortDriftIgnorePorts = []string{}
	}
	return cp
}
