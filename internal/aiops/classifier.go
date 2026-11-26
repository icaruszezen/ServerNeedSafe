package aiops

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// RiskClass categorizes remote SSH/SFTP operations for Human-in-the-Loop gating.
type RiskClass string

const (
	RiskReadOnly RiskClass = "readonly" // Safe inspection probe; auto-executed in standard & autonomous modes
	RiskMutating RiskClass = "mutating" // State-changing command; requires approval in standard mode
	RiskBlocked  RiskClass = "blocked"  // Catastrophic command; hard-blocked in ALL modes
)

var (
	blockedPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(^|[;&|\s])rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive|--no-preserve-root)[a-zA-Z\s-]*\s+(/|/\*)\s*($|[;&|])`),
		regexp.MustCompile(`(?i)--no-preserve-root`),
		regexp.MustCompile(`(?i)(^|[;&|\s])(mkfs(\.[a-z0-9]+)?|wipefs|fdisk|parted|sfdisk)\b`),
		regexp.MustCompile(`(?i)(^|[;&|\s])diskutil\s+(eraseDisk|eraseVolume|zeroDisk|randomDisk|partitionDisk|apfs\s+deleteContainer|apfs\s+deleteVolume)\b`),
		regexp.MustCompile(`(?i)(^|[;&|\s])dd\s+[^;&|]*of=/dev/(sd|vd|nvme|xvd|mmcblk|loop|dm-|disk|rdisk)`),
		regexp.MustCompile(`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:`),
		regexp.MustCompile(`(?i)(^|[;&|\s])(shutdown|poweroff|halt|init\s+0|reboot\s+-f)\b`),
		regexp.MustCompile(`(?i)>\s*/dev/(sd|vd|nvme|xvd|disk|rdisk)[a-z0-9]*`),
		regexp.MustCompile(`(?i)(^|[;&|\s])(chmod|chown)\s+(-[a-zA-Z]*R[a-zA-Z]*\s+)\S+\s+/\s*($|[;&|])`),
	}

	safeSimpleCommands = map[string]bool{
		"uname":      true,
		"hostname":   true,
		"uptime":     true,
		"whoami":     true,
		"id":         true,
		"w":          true,
		"who":        true,
		"last":       true,
		"lastb":      true,
		"date":       true,
		"timedatectl": false, // checked below for status-only
		"free":       true,
		"vmstat":     true,
		"iostat":     true,
		"mpstat":     true,
		"df":         true,
		"du":         true,
		"ls":         true,
		"stat":       true,
		"file":       true,
		"pwd":        true,
		"which":      true,
		"type":       true,
		"cat":        true,
		"head":       true,
		"tail":       true,
		"grep":       true,
		"egrep":      true,
		"fgrep":      true,
		"cut":        true,
		"sort":       true,
		"uniq":       true,
		"wc":         true,
		"tr":         true,
		"ps":         true,
		"pgrep":      true,
		"lsof":       true,
		"ss":         true,
		"netstat":    true,
		"ifconfig":   true,
		"dig":        true,
		"nslookup":   true,
		"host":       true,
		"lsblk":      true,
		"lscpu":      true,
		"lsmod":      true,
		"lspci":      true,
		"dmesg":      true,
		"journalctl": true,
		"getenforce":      true,
		"sestatus":        true,
		"aa-status":       true,
		"sw_vers":         true,
		"vm_stat":         true,
		"pagesize":        true,
		"ioreg":           true,
		"system_profiler": true,
		"echo":            true,
		"printf":          true,
		"true":            true,
	}

	safeRedirectCleaner = regexp.MustCompile(`2>\s*/dev/null|2>&1|>&2`)
)

// ClassifyCommand inspects a shell command string and classifies it as RiskReadOnly, RiskMutating, or RiskBlocked.
func ClassifyCommand(raw string) (RiskClass, string) {
	cmd := strings.TrimSpace(raw)
	if cmd == "" {
		return RiskMutating, "空命令"
	}

	for _, re := range blockedPatterns {
		if re.MatchString(cmd) {
			return RiskBlocked, "命中毁灭性高危指令黑名单（系统级删除/格式化/断电），已被安全熔断器硬拦截"
		}
	}

	// Subshells or command substitution can hide arbitrary mutations
	if strings.Contains(cmd, "`") || strings.Contains(cmd, "$(") {
		return RiskMutating, "包含子 Shell 命令替换 ($(...) / 反引号)，需人工审阅确认"
	}

	// Strip benign stderr redirections before checking file write operators
	cleaned := safeRedirectCleaner.ReplaceAllString(cmd, " ")
	if strings.Contains(cleaned, ">") || strings.Contains(cleaned, "<<") {
		return RiskMutating, "包含文件输出重定向写入操作 (> / >>)"
	}

	// Split compound pipelines and boolean chains
	segments := splitShellSegments(cleaned)
	if len(segments) == 0 {
		return RiskMutating, "无法解析的复合指令"
	}

	for _, seg := range segments {
		ok, why := isSegmentReadOnly(seg)
		if !ok {
			return RiskMutating, why
		}
	}
	return RiskReadOnly, "只读诊断探测命令"
}

func splitShellSegments(s string) []string {
	var out []string
	var cur strings.Builder
	inSingle := false
	inDouble := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			cur.WriteByte(ch)
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			cur.WriteByte(ch)
			continue
		}
		if !inSingle && !inDouble {
			if ch == ';' || ch == '|' || ch == '\n' {
				if i+1 < len(s) && s[i+1] == ch {
					i++
				}
				if trimmed := strings.TrimSpace(cur.String()); trimmed != "" {
					out = append(out, trimmed)
				}
				cur.Reset()
				continue
			}
			if ch == '&' {
				if i+1 < len(s) && s[i+1] == '&' {
					i++
					if trimmed := strings.TrimSpace(cur.String()); trimmed != "" {
						out = append(out, trimmed)
					}
					cur.Reset()
					continue
				}
				// Background single '&'
				return nil
			}
		}
		cur.WriteByte(ch)
	}
	if trimmed := strings.TrimSpace(cur.String()); trimmed != "" {
		out = append(out, trimmed)
	}
	return out
}

func isSegmentReadOnly(seg string) (bool, string) {
	fields := strings.Fields(seg)
	if len(fields) == 0 {
		return true, ""
	}

	// Strip leading env assignments like LANG=C LC_ALL=C
	for len(fields) > 0 && strings.Contains(fields[0], "=") && !strings.HasPrefix(fields[0], "-") {
		fields = fields[1:]
	}
	if len(fields) == 0 {
		return false, "仅包含环境变量赋值"
	}

	bin := fields[0]
	args := fields[1:]

	if bin == "sudo" {
		return false, "包含 sudo 提权执行，需人工确认"
	}

	if safe, exists := safeSimpleCommands[bin]; exists && safe {
		// Guard infinite-blocking flags on tail/top/journalctl
		if bin == "tail" && slices.ContainsFunc(args, func(a string) bool { return a == "-f" || a == "-F" || a == "--follow" }) {
			return false, "tail -f 持续阻塞流不能作为一次性探针自动执行"
		}
		if bin == "journalctl" && slices.ContainsFunc(args, func(a string) bool { return a == "-f" || a == "--follow" || strings.HasPrefix(a, "--vacuum") }) {
			return false, "journalctl 日志清理或阻塞跟随操作需人工审批"
		}
		return true, ""
	}

	switch bin {
	case "top":
		if slices.ContainsFunc(args, func(a string) bool { return strings.Contains(a, "b") && strings.HasPrefix(a, "-") }) {
			return true, ""
		}
		// macOS non-interactive batch mode: top -l <positive_count> (reject -l 0 which streams infinitely)
		for i, a := range args {
			if a == "-l" && i+1 < len(args) && isPositiveIntArg(args[i+1]) {
				return true, ""
			}
			if strings.HasPrefix(a, "-l") && len(a) > 2 && isPositiveIntArg(a[2:]) {
				return true, ""
			}
		}
		return false, "交互式 top 缺少批处理参数 (-bn1 或 macOS -l <次数>)"
	case "ping":
		if slices.Contains(args, "-c") {
			return true, ""
		}
		return false, "无限次数 ping 缺少 -c 计数限制"
	case "awk":
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "system(") || strings.Contains(joined, "|") {
			return false, "awk 脚本包含外部命令调用"
		}
		return true, ""
	case "sed":
		for _, a := range args {
			if a == "-i" || strings.HasPrefix(a, "-i") || a == "--in-place" {
				return false, "sed -i 原地修改文件操作需人工审批"
			}
		}
		return true, ""
	case "find":
		for _, a := range args {
			if a == "-delete" || a == "-exec" || a == "-execdir" || a == "-ok" || a == "-fprint" {
				return false, fmt.Sprintf("find 包含变更/执行参数 (%s)，需人工审批", a)
			}
		}
		return true, ""
	case "systemctl":
		if len(args) > 0 {
			sub := args[0]
			for _, a := range args {
				if !strings.HasPrefix(a, "-") {
					sub = a
					break
				}
			}
			switch sub {
			case "status", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files", "list-timers", "show":
				return true, ""
			}
			return false, fmt.Sprintf("systemctl %s 属于服务状态变更操作", sub)
		}
		return true, ""
	case "service":
		if len(args) >= 2 && args[1] == "status" {
			return true, ""
		}
		return false, "service 服务控制操作需人工审批"
	case "docker", "podman":
		if len(args) > 0 {
			switch args[0] {
			case "ps", "images", "info", "version", "inspect", "logs", "top", "port", "diff":
				if args[0] == "logs" && slices.Contains(args, "-f") {
					return false, "docker logs -f 持续跟随不能自动执行"
				}
				return true, ""
			case "stats":
				if slices.Contains(args, "--no-stream") {
					return true, ""
				}
				return false, "docker stats 缺少 --no-stream 参数"
			case "network", "volume":
				if len(args) >= 2 && (args[1] == "ls" || args[1] == "inspect") {
					return true, ""
				}
			}
		}
		return false, fmt.Sprintf("%s 容器变更操作需人工审批", bin)
	case "ip":
		if len(args) == 0 {
			return true, ""
		}
		for _, a := range args {
			if a == "add" || a == "del" || a == "delete" || a == "set" || a == "flush" || a == "replace" {
				return false, "ip 网络配置修改操作需人工审批"
			}
		}
		return true, ""
	case "sysctl":
		for _, a := range args {
			if a == "-w" || a == "-p" || strings.Contains(a, "=") {
				return false, "sysctl 内核参数写入需人工审批"
			}
		}
		return true, ""
	case "ufw":
		if len(args) > 0 && args[0] == "status" {
			return true, ""
		}
		return false, "ufw 防火墙规则变更需人工审批"
	case "iptables", "ip6tables":
		if slices.Contains(args, "-L") || slices.Contains(args, "-S") {
			for _, a := range args {
				if a == "-A" || a == "-I" || a == "-D" || a == "-F" || a == "-P" || a == "-X" {
					return false, "iptables 防火墙规则修改需人工审批"
				}
			}
			return true, ""
		}
		return false, "iptables 防火墙规则修改需人工审批"
	case "nginx":
		if len(args) == 1 && (args[0] == "-t" || args[0] == "-T" || args[0] == "-v" || args[0] == "-V") {
			return true, ""
		}
		return false, "nginx 控制指令需人工审批"
	case "sshd":
		if len(args) == 1 && (args[0] == "-t" || args[0] == "-T") {
			return true, ""
		}
		return false, "sshd 执行指令需人工审批"
	case "dpkg":
		if len(args) > 0 && (args[0] == "-l" || args[0] == "-s" || args[0] == "-L") {
			return true, ""
		}
		return false, "dpkg 软件包操作需人工审批"
	case "rpm":
		if len(args) > 0 && strings.HasPrefix(args[0], "-q") {
			return true, ""
		}
		return false, "rpm 软件包操作需人工审批"
	case "memory_pressure":
		for _, a := range args {
			if a == "-S" || a == "-l" || a == "-p" {
				return false, "memory_pressure 压力模拟参数需人工审批"
			}
		}
		return true, ""
	case "csrutil":
		if len(args) == 1 && args[0] == "status" {
			return true, ""
		}
		return false, "csrutil 安全配置变更需人工审批"
	case "launchctl":
		if len(args) > 0 {
			switch args[0] {
			case "list", "print", "blame", "procinfo", "dumpstate":
				return true, ""
			}
		}
		return false, "launchctl 服务状态变更操作需人工审批"
	case "diskutil":
		if len(args) > 0 {
			switch args[0] {
			case "list", "info":
				return true, ""
			case "apfs", "cs":
				if len(args) >= 2 && args[1] == "list" {
					return true, ""
				}
			}
		}
		return false, "diskutil 磁盘变更操作需人工审批"
	case "scutil":
		if len(args) > 0 && !slices.Contains(args, "--set") {
			switch args[0] {
			case "--dns", "--proxy", "--nwi", "--get":
				return true, ""
			}
		}
		return false, "scutil 系统网络配置变更需人工审批"
	case "networksetup":
		if len(args) > 0 && (strings.HasPrefix(args[0], "-list") || strings.HasPrefix(args[0], "-get")) {
			for _, a := range args[1:] {
				if strings.HasPrefix(a, "-set") || strings.HasPrefix(a, "-create") || strings.HasPrefix(a, "-delete") || strings.HasPrefix(a, "-remove") || strings.HasPrefix(a, "-rename") {
					return false, "networksetup 网络变更操作需人工审批"
				}
			}
			return true, ""
		}
		return false, "networksetup 网络变更操作需人工审批"
	case "pmset":
		if len(args) >= 1 && args[0] == "-g" {
			for _, a := range args[1:] {
				if a == "-a" || a == "-b" || a == "-c" || a == "-u" || a == "sleepnow" || a == "schedule" || a == "repeat" {
					return false, "pmset 电源策略变更操作需人工审批"
				}
			}
			return true, ""
		}
		return false, "pmset 电源策略变更操作需人工审批"
	case "log":
		if len(args) > 0 && args[0] == "show" {
			return true, ""
		}
		return false, "log 流式监听或配置变更操作需人工审批"
	case "dscl":
		hasReadOp := false
		for _, a := range args {
			switch a {
			case "-create", "-delete", "-append", "-merge", "-change", "-changei", "-passwd", "-createprop", "-deleteprop":
				return false, "dscl 目录账户变更操作需人工审批"
			case "-list", "-read", "-readall", "-search":
				hasReadOp = true
			}
		}
		if hasReadOp {
			return true, ""
		}
		return false, "dscl 目录操作需人工审批"
	case "defaults":
		if len(args) > 0 {
			switch args[0] {
			case "read", "read-type", "find", "domains":
				return true, ""
			}
		}
		return false, "defaults 系统偏好写入操作需人工审批"
	case "plutil":
		if len(args) > 0 && (args[0] == "-p" || args[0] == "-lint") {
			return true, ""
		}
		return false, "plutil 属性表修改操作需人工审批"
	case "pfctl":
		hasShow := false
		for _, a := range args {
			if a == "-s" || a == "-sr" || a == "-sn" || a == "-si" || a == "-sa" || a == "-ss" || a == "-sm" || a == "-st" {
				hasShow = true
			} else if a == "-e" || a == "-d" || a == "-f" || a == "-F" || a == "-k" || a == "-K" || a == "-X" || a == "-T" {
				return false, "pfctl 防火墙规则变更需人工审批"
			}
		}
		if hasShow {
			return true, ""
		}
		return false, "pfctl 防火墙规则变更需人工审批"
	case "brew":
		if len(args) > 0 {
			switch args[0] {
			case "list", "info", "outdated", "config", "doctor", "--version", "-v":
				return true, ""
			case "services":
				if len(args) >= 2 && (args[1] == "list" || args[1] == "info") {
					return true, ""
				}
			}
		}
		return false, "brew 软件包或服务变更操作需人工审批"
	case "socketfilterfw", "/usr/libexec/ApplicationFirewall/socketfilterfw":
		if len(args) == 1 {
			switch args[0] {
			case "--getglobalstate", "--getblockall", "--getstealthmode", "--getallowsigned", "--listapps":
				return true, ""
			}
		}
		return false, "socketfilterfw 防火墙规则变更需人工审批"
	}

	return false, fmt.Sprintf("涉及状态变更或未列入只读白名单的指令 (%s)", bin)
}

func isPositiveIntArg(s string) bool {
	if s == "" {
		return false
	}
	nonZero := false
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
		if ch != '0' {
			nonZero = true
		}
	}
	return nonZero
}

// BuildUnifiedDiff computes a compact, readable unified diff between oldContent and newContent.
func BuildUnifiedDiff(filePath, oldContent, newContent string) string {
	cleanPath := strings.TrimPrefix(filePath, "/")
	if cleanPath == "" {
		cleanPath = "remote_file"
	}

	oldLines := splitLinesNormalized(oldContent)
	newLines := splitLinesNormalized(newContent)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("--- a/%s\n", cleanPath))
	sb.WriteString(fmt.Sprintf("+++ b/%s\n", cleanPath))

	if oldContent == newContent {
		sb.WriteString("@@ 无内容变更 @@\n")
		return sb.String()
	}

	// LCS matrix for files up to reasonable line counts; fallback to prefix/suffix diff for very large files
	if len(oldLines)*len(newLines) <= 400_000 {
		ops := computeDiffOps(oldLines, newLines)
		writeDiffHunks(&sb, ops, 3)
		return sb.String()
	}

	// Fast prefix/suffix diff for large files
	prefix := 0
	for prefix < len(oldLines) && prefix < len(newLines) && oldLines[prefix] == newLines[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(oldLines)-prefix && suffix < len(newLines)-prefix &&
		oldLines[len(oldLines)-1-suffix] == newLines[len(newLines)-1-suffix] {
		suffix++
	}

	sb.WriteString(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", prefix+1, len(oldLines)-prefix-suffix, prefix+1, len(newLines)-prefix-suffix))
	startCtx := max(0, prefix-2)
	for i := startCtx; i < prefix; i++ {
		sb.WriteString(" " + oldLines[i] + "\n")
	}
	for i := prefix; i < len(oldLines)-suffix; i++ {
		sb.WriteString("-" + oldLines[i] + "\n")
	}
	for i := prefix; i < len(newLines)-suffix; i++ {
		sb.WriteString("+" + newLines[i] + "\n")
	}
	endIdx := len(oldLines) - suffix
	for i := endIdx; i < min(len(oldLines), endIdx+2); i++ {
		sb.WriteString(" " + oldLines[i] + "\n")
	}
	return sb.String()
}

type diffOp struct {
	kind byte // ' ', '-', '+'
	line string
}

func splitLinesNormalized(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

func computeDiffOps(a, b []string) []diffOp {
	m, n := len(a), len(b)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	for i := m - 1; i >= 0; i-- {
		for j := n - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}

	ops := make([]diffOp, 0, m+n)
	i, j := 0, 0
	for i < m && j < n {
		if a[i] == b[j] {
			ops = append(ops, diffOp{kind: ' ', line: a[i]})
			i++
			j++
		} else if dp[i+1][j] >= dp[i][j+1] {
			ops = append(ops, diffOp{kind: '-', line: a[i]})
			i++
		} else {
			ops = append(ops, diffOp{kind: '+', line: b[j]})
			j++
		}
	}
	for ; i < m; i++ {
		ops = append(ops, diffOp{kind: '-', line: a[i]})
	}
	for ; j < n; j++ {
		ops = append(ops, diffOp{kind: '+', line: b[j]})
	}
	return ops
}

func writeDiffHunks(sb *strings.Builder, ops []diffOp, ctxLines int) {
	keep := make([]bool, len(ops))
	for idx, op := range ops {
		if op.kind != ' ' {
			lo := max(0, idx-ctxLines)
			hi := min(len(ops)-1, idx+ctxLines)
			for k := lo; k <= hi; k++ {
				keep[k] = true
			}
		}
	}

	inHunk := false
	for idx, op := range ops {
		if keep[idx] {
			if !inHunk {
				sb.WriteString("@@ 变更片段 @@\n")
				inHunk = true
			}
			sb.WriteByte(op.kind)
			sb.WriteString(op.line)
			sb.WriteByte('\n')
		} else {
			inHunk = false
		}
	}
}
