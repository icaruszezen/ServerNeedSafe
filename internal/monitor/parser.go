package monitor

import (
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

type rawCounterSample struct {
	uptimeSec float64
	cpuFields []uint64
	cpuPct    []float64 // Direct percentage sample fallback (e.g., macOS top/iostat: total user sys iowait steal)
	ctxt      uint64
	netByDev  map[string]rawNetDev
	bioByDev  map[string]rawBlockDev
}

type rawNetDev struct {
	rxBytes, rxPkts, rxErrs, rxDrops int64
	txBytes, txPkts, txErrs, txDrops int64
}

type rawBlockDev struct {
	rdIOs, rdSectors int64
	wrIOs, wrSectors int64
}

var (
	ssUsersRegex = regexp.MustCompile(`\(\("([^"]+)",pid=(\d+)`)
)

func roundOne(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return math.Round(v*10) / 10
}

func formatUptimeHuman(sec int64) string {
	if sec <= 0 {
		return "0m"
	}
	days := sec / 86400
	hours := (sec % 86400) / 3600
	mins := (sec % 3600) / 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}

func newRawCounterSample() *rawCounterSample {
	return &rawCounterSample{
		netByDev: make(map[string]rawNetDev),
		bioByDev: make(map[string]rawBlockDev),
	}
}

func parseSampleLine(line string, dst *rawCounterSample) {
	idx := strings.IndexByte(line, '=')
	if idx <= 0 {
		return
	}
	k := line[:idx]
	v := strings.TrimSpace(line[idx+1:])
	switch k {
	case "UP":
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			dst.uptimeSec = f
		}
	case "CTXT":
		if u, err := strconv.ParseUint(v, 10, 64); err == nil {
			dst.ctxt = u
		}
	case "CPU":
		fields := strings.Fields(v)
		// fields[0] is "cpu", followed by user nice system idle iowait irq softirq steal ...
		if len(fields) >= 5 && fields[0] == "cpu" {
			nums := make([]uint64, 0, len(fields)-1)
			for _, f := range fields[1:] {
				n, err := strconv.ParseUint(f, 10, 64)
				if err != nil {
					break
				}
				nums = append(nums, n)
			}
			dst.cpuFields = nums
		}
	case "CPU_PCT":
		fields := strings.Fields(v)
		if len(fields) >= 3 {
			vals := make([]float64, 0, len(fields))
			for _, f := range fields {
				n, err := strconv.ParseFloat(f, 64)
				if err != nil {
					break
				}
				vals = append(vals, n)
			}
			if len(vals) >= 3 {
				dst.cpuPct = vals
			}
		}
	case "NET":
		f := strings.Fields(v)
		if len(f) >= 9 {
			dev := f[0]
			n := rawNetDev{}
			n.rxBytes, _ = strconv.ParseInt(f[1], 10, 64)
			n.rxPkts, _ = strconv.ParseInt(f[2], 10, 64)
			n.rxErrs, _ = strconv.ParseInt(f[3], 10, 64)
			n.rxDrops, _ = strconv.ParseInt(f[4], 10, 64)
			n.txBytes, _ = strconv.ParseInt(f[5], 10, 64)
			n.txPkts, _ = strconv.ParseInt(f[6], 10, 64)
			n.txErrs, _ = strconv.ParseInt(f[7], 10, 64)
			n.txDrops, _ = strconv.ParseInt(f[8], 10, 64)
			dst.netByDev[dev] = n
		}
	case "BIO":
		f := strings.Fields(v)
		if len(f) >= 5 {
			dev := f[0]
			b := rawBlockDev{}
			b.rdIOs, _ = strconv.ParseInt(f[1], 10, 64)
			b.rdSectors, _ = strconv.ParseInt(f[2], 10, 64)
			b.wrIOs, _ = strconv.ParseInt(f[3], 10, 64)
			b.wrSectors, _ = strconv.ParseInt(f[4], 10, 64)
			dst.bioByDev[dev] = b
		}
	}
}

func sumBlockDevices(bio map[string]rawBlockDev) (readBytes, writeBytes, ioOps int64) {
	hasPhysical := false
	for dev := range bio {
		if !strings.HasPrefix(dev, "dm-") {
			hasPhysical = true
			break
		}
	}
	for dev, b := range bio {
		if hasPhysical && strings.HasPrefix(dev, "dm-") {
			continue
		}
		readBytes += b.rdSectors * 512
		writeBytes += b.wrSectors * 512
		ioOps += b.rdIOs + b.wrIOs
	}
	return
}

func isCountedNIC(name string) bool {
	if name == "" || name == "lo" || name == "lo0" {
		return false
	}
	if strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "virbr") {
		return false
	}
	if strings.HasPrefix(name, "gif") || strings.HasPrefix(name, "stf") || strings.HasPrefix(name, "awdl") ||
		strings.HasPrefix(name, "llw") || strings.HasPrefix(name, "anpi") || strings.HasPrefix(name, "XHC") ||
		strings.HasPrefix(name, "pktap") || strings.HasPrefix(name, "iptap") || strings.HasPrefix(name, "bridge") {
		return false
	}
	return true
}

func classifyBindExposure(cleanAddr string) (exposed bool, scope string) {
	if cleanAddr == "" || cleanAddr == "0.0.0.0" || cleanAddr == "*" || cleanAddr == "::" {
		return true, "wildcard"
	}
	ip, err := netip.ParseAddr(cleanAddr)
	if err != nil {
		// Fallback for unusual interface/hostname tokens
		if strings.HasPrefix(cleanAddr, "127.") || cleanAddr == "::1" || strings.EqualFold(cleanAddr, "localhost") {
			return false, "loopback"
		}
		return true, "public_ip"
	}
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return false, "loopback"
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return false, "link_local"
	}
	if ip.IsUnspecified() {
		return true, "wildcard"
	}
	if ip.IsPrivate() {
		// In VPC/cloud servers, NIC-bound private IPv4 (10.x/172.16.x/192.168.x) is network-reachable (and often EIP-mapped)
		return true, "private_ip"
	}
	return true, "public_ip"
}

func parseHostPortEndpoint(ep string) (bindAddr string, port int, publicExposed bool, exposureScope string, ok bool) {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return "", 0, false, "", false
	}
	lastColon := strings.LastIndexByte(ep, ':')
	if lastColon <= 0 || lastColon == len(ep)-1 {
		return "", 0, false, "", false
	}
	portStr := ep[lastColon+1:]
	if portStr == "*" {
		return "", 0, false, "", false
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return "", 0, false, "", false
	}
	addr := ep[:lastColon]
	// Strip interface scope suffix like 127.0.0.53%lo, [::]%eth0, or [fe80::1%lo0]
	if pctIdx := strings.IndexByte(addr, '%'); pctIdx > 0 {
		hasBracket := strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]")
		addr = addr[:pctIdx]
		if hasBracket && !strings.HasSuffix(addr, "]") {
			addr += "]"
		}
	}
	cleanAddr := strings.Trim(addr, "[]")
	isExposed, scope := classifyBindExposure(cleanAddr)
	if addr == "" {
		addr = "*"
	}
	return addr, p, isExposed, scope, true
}

func parseListeningPortLine(line string) (vault.ListeningPortStat, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return vault.ListeningPortStat{}, false
	}
	proto := strings.ToLower(fields[0])
	if !strings.HasPrefix(proto, "tcp") && !strings.HasPrefix(proto, "udp") {
		return vault.ListeningPortStat{}, false
	}

	localField := ""
	if len(fields) >= 5 && (fields[1] == "LISTEN" || fields[1] == "UNCONN" || fields[1] == "ESTAB") {
		if strings.HasPrefix(proto, "tcp") && fields[1] != "LISTEN" {
			return vault.ListeningPortStat{}, false
		}
		localField = fields[4]
	} else {
		if strings.HasPrefix(proto, "tcp") && !strings.Contains(line, "LISTEN") {
			return vault.ListeningPortStat{}, false
		}
		localField = fields[3]
	}

	bindAddr, port, isExposed, scope, ok := parseHostPortEndpoint(localField)
	if !ok {
		return vault.ListeningPortStat{}, false
	}

	stat := vault.ListeningPortStat{
		Proto:         proto,
		BindAddr:      bindAddr,
		Port:          port,
		PublicExposed: isExposed,
		ExposureScope: scope,
	}

	if m := ssUsersRegex.FindStringSubmatch(line); len(m) == 3 {
		stat.Process = m[1]
		stat.PID, _ = strconv.Atoi(m[2])
	} else {
		last := fields[len(fields)-1]
		if slash := strings.IndexByte(last, '/'); slash > 0 {
			if pid, err := strconv.Atoi(last[:slash]); err == nil {
				stat.PID = pid
				stat.Process = strings.TrimSuffix(last[slash+1:], ":")
			}
		}
	}
	return stat, true
}

func applyCPUDelta(snap *vault.ServerMonitorSnapshot, fromTicks, toTicks []uint64) bool {
	if len(fromTicks) < 4 || len(toTicks) < len(fromTicks) {
		return false
	}
	var sum0, sum1 uint64
	for i := range fromTicks {
		sum0 += fromTicks[i]
		sum1 += toTicks[i]
	}
	if sum1 <= sum0 {
		return false
	}
	totD := float64(sum1 - sum0)
	getD := func(idx int) float64 {
		if idx < len(fromTicks) && toTicks[idx] >= fromTicks[idx] {
			return float64(toTicks[idx] - fromTicks[idx])
		}
		return 0
	}
	userD := getD(0) + getD(1)          // user + nice
	sysD := getD(2) + getD(5) + getD(6) // system + irq + softirq
	idleD := getD(3)                    // idle
	iowaitD := getD(4)                  // iowait
	stealD := getD(7)                   // steal

	snap.CPUPercent = roundOne(math.Max(0, math.Min(100, (totD-idleD)*100.0/totD)))
	snap.CPUUserPct = roundOne(userD * 100.0 / totD)
	snap.CPUSystemPct = roundOne(sysD * 100.0 / totD)
	snap.CPUIowaitPct = roundOne(iowaitD * 100.0 / totD)
	snap.CPUStealPct = roundOne(stealD * 100.0 / totD)
	return true
}

// ParseDeepTelemetry parses multi-section agentless SSH output into a structured ServerMonitorSnapshot.
func ParseDeepTelemetry(raw string, snap *vault.ServerMonitorSnapshot, prev *vault.ServerMonitorSnapshot) {
	if snap == nil {
		return
	}
	sections := make(map[string][]string)
	curSec := ""
	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" || line == "===SNS_END===" {
			continue
		}
		if strings.HasPrefix(line, "===SNS_SEC:") && strings.HasSuffix(line, "===") {
			curSec = strings.TrimSuffix(strings.TrimPrefix(line, "===SNS_SEC:"), "===")
			continue
		}
		if curSec != "" {
			sections[curSec] = append(sections[curSec], line)
		}
	}

	t0 := newRawCounterSample()
	for _, l := range sections["SAMPLE_T0"] {
		parseSampleLine(l, t0)
	}
	t1 := newRawCounterSample()
	hasT1 := len(sections["SAMPLE_T1"]) > 0
	for _, l := range sections["SAMPLE_T1"] {
		parseSampleLine(l, t1)
	}
	latest := t0
	if hasT1 {
		latest = t1
	}

	// 1. System Identity, Load & Clock Offset
	for _, l := range sections["SYS"] {
		idx := strings.IndexByte(l, '=')
		if idx <= 0 {
			continue
		}
		k, v := l[:idx], strings.TrimSpace(l[idx+1:])
		switch k {
		case "HOSTNAME":
			snap.Hostname = v
		case "OS":
			snap.OS = v
		case "KERNEL":
			snap.Kernel = v
		case "ARCH":
			snap.Arch = v
		case "CPU_MODEL":
			snap.CPUModel = v
		case "VIRT":
			if v != "none" {
				snap.Virtualization = v
			}
		case "CORES":
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				snap.CPUCores = n
			}
		case "UPTIME_SEC":
			if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
				snap.UptimeSec = int64(f)
				snap.Uptime = formatUptimeHuman(snap.UptimeSec)
				if !snap.CollectedAt.IsZero() {
					snap.BootTime = snap.CollectedAt.Add(-time.Duration(snap.UptimeSec) * time.Second).UTC().Format(time.RFC3339)
				}
			}
		case "LOAD":
			parts := strings.Fields(v)
			if len(parts) >= 3 {
				snap.Load1, _ = strconv.ParseFloat(parts[0], 64)
				snap.Load5, _ = strconv.ParseFloat(parts[1], 64)
				snap.Load15, _ = strconv.ParseFloat(parts[2], 64)
			}
		case "SERVER_TIME":
			snap.ServerTime = v
		case "SERVER_EPOCH":
			if ep, err := strconv.ParseInt(v, 10, 64); err == nil && ep > 1577836800 {
				snap.RawServerEpoch = ep
				if !snap.CollectedAt.IsZero() {
					snap.ClockOffsetSec = ep - snap.CollectedAt.Unix()
				}
			}
		case "TIMEZONE":
			snap.Timezone = v
		case "NTP":
			snap.NTPSynced = strings.EqualFold(v, "yes") || v == "1" || strings.EqualFold(v, "true")
		case "TEMP_C":
			if t, err := strconv.ParseFloat(v, 64); err == nil && t > 0 && t < 150 {
				snap.CPUTempC = roundOne(t)
			}
		}
	}
	if snap.CPUCores <= 0 {
		if prev != nil && prev.CPUCores > 0 {
			snap.CPUCores = prev.CPUCores
		} else {
			snap.CPUCores = 1
		}
	}
	snap.LoadPerCore = roundOne(snap.Load1 / float64(snap.CPUCores))

	// 2. CPU Breakdown & Context Switch Rate
	// Prefer sustained cross-interval delta (prev.RawCPUTicks -> latest.cpuFields) to avoid 250ms spike noise & self-observation bias;
	// fallback cleanly to same-script T0 -> T1 delta or macOS CPU_PCT.
	if len(latest.cpuFields) >= 4 {
		snap.RawCPUTicks = slices.Clone(latest.cpuFields)
	}
	snap.RawContextSwitches = latest.ctxt
	snap.RawSampleUptime = latest.uptimeSec

	prevElapsed := 0.0
	if prev != nil && prev.Reachable && !prev.CollectedAt.IsZero() && !snap.CollectedAt.IsZero() {
		el := snap.CollectedAt.Sub(prev.CollectedAt).Seconds()
		if el >= 3.0 && el <= 3600.0 {
			prevElapsed = el
		}
	}

	dt := 0.0
	if hasT1 {
		dt = t1.uptimeSec - t0.uptimeSec
		if dt <= 0.02 {
			dt = 0.25
		}
	}

	cpuComputed := false
	// When the script explicitly captured an isolated T0->T1 pair (initial sweep / synthetic fixture),
	// honor T0->T1 deterministically; when T1 is omitted (steady-state zero-sleep sweeps with hasPrevCPU=true),
	// compute the sustained cross-interval delta from prev.RawCPUTicks -> T0.
	if hasT1 && len(t0.cpuFields) >= 4 && len(t1.cpuFields) >= len(t0.cpuFields) {
		if applyCPUDelta(snap, t0.cpuFields, t1.cpuFields) {
			cpuComputed = true
		}
		if t1.ctxt > t0.ctxt && dt > 0 {
			snap.ContextSwSec = int64(float64(t1.ctxt-t0.ctxt) / dt)
		}
	}
	if !cpuComputed && prevElapsed > 0 && prev != nil && len(prev.RawCPUTicks) >= 4 && len(latest.cpuFields) >= len(prev.RawCPUTicks) {
		if applyCPUDelta(snap, prev.RawCPUTicks, latest.cpuFields) {
			cpuComputed = true
			if latest.ctxt > prev.RawContextSwitches {
				snap.ContextSwSec = int64(float64(latest.ctxt-prev.RawContextSwitches) / prevElapsed)
			}
		}
	}
	if !cpuComputed {
		pctSrc := t1.cpuPct
		if len(pctSrc) < 3 {
			pctSrc = t0.cpuPct
		}
		if len(pctSrc) >= 3 {
			clampPct := func(v float64) float64 {
				return roundOne(math.Max(0, math.Min(100, v)))
			}
			snap.CPUPercent = clampPct(pctSrc[0])
			snap.CPUUserPct = clampPct(pctSrc[1])
			snap.CPUSystemPct = clampPct(pctSrc[2])
			if len(pctSrc) >= 4 {
				snap.CPUIowaitPct = clampPct(pctSrc[3])
			}
			if len(pctSrc) >= 5 {
				snap.CPUStealPct = clampPct(pctSrc[4])
			}
		}
	}

	// 3. Memory, Swap, File Descriptors, OOM
	memKV := make(map[string]int64)
	for _, l := range sections["MEM"] {
		idx := strings.IndexByte(l, '=')
		if idx <= 0 {
			continue
		}
		k, v := l[:idx], strings.TrimSpace(l[idx+1:])
		switch k {
		case "FILE_NR":
			parts := strings.Fields(v)
			if len(parts) >= 2 {
				snap.FDUsed, _ = strconv.ParseInt(parts[0], 10, 64)
				snap.FDMax, _ = strconv.ParseInt(parts[1], 10, 64)
				if snap.FDMax > 0 {
					snap.FDPercent = roundOne(float64(snap.FDUsed) * 100.0 / float64(snap.FDMax))
				}
			}
		case "OOM_KILL":
			snap.OOMKills, _ = strconv.ParseInt(v, 10, 64)
		default:
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				memKV[k] = n
			}
		}
	}
	if totalKB := memKV["MemTotal"]; totalKB > 0 {
		availKB, hasAvail := memKV["MemAvailable"]
		bufKB := memKV["Buffers"]
		cacheKB := memKV["Cached"] + memKV["SReclaimable"]
		if !hasAvail {
			availKB = memKV["MemFree"] + bufKB + cacheKB
		}
		usedKB := max(int64(0), totalKB-availKB)
		snap.MemTotalMB = totalKB / 1024
		snap.MemUsedMB = usedKB / 1024
		snap.MemAvailableMB = availKB / 1024
		snap.MemBuffersMB = bufKB / 1024
		snap.MemCachedMB = cacheKB / 1024
		snap.MemPercent = roundOne(float64(usedKB) * 100.0 / float64(totalKB))
	}
	if swapTotalKB := memKV["SwapTotal"]; swapTotalKB > 0 {
		swapUsedKB := max(int64(0), swapTotalKB-memKV["SwapFree"])
		snap.SwapTotalMB = swapTotalKB / 1024
		snap.SwapUsedMB = swapUsedKB / 1024
		snap.SwapPercent = roundOne(float64(swapUsedKB) * 100.0 / float64(swapTotalKB))
	}

	// 4. Multi-Partition Disk Capacity, Inodes & Mount Health (RO / Remote)
	inodeByMount := make(map[string]float64)
	for _, l := range sections["INODE"] {
		if !strings.HasPrefix(l, "INODE=") {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(l, "INODE="), "|", 2)
		if len(parts) == 2 {
			pctStr := strings.TrimSuffix(strings.TrimSpace(parts[1]), "%")
			if pct, err := strconv.ParseFloat(pctStr, 64); err == nil {
				inodeByMount[strings.TrimSpace(parts[0])] = pct
			}
		}
	}

	seenMounts := make(map[string]bool)
	for _, l := range sections["DISK"] {
		if !strings.HasPrefix(l, "FS=") {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(l, "FS="), "|")
		if len(parts) < 7 {
			continue
		}
		dev, fsType := parts[0], parts[1]
		totalKB, e1 := strconv.ParseFloat(parts[2], 64)
		usedKB, e2 := strconv.ParseFloat(parts[3], 64)
		availKB, _ := strconv.ParseFloat(parts[4], 64)
		capStr := strings.TrimSpace(parts[5])
		mount := parts[6]
		if e1 != nil || e2 != nil || totalKB <= 0 || !strings.HasSuffix(capStr, "%") || seenMounts[mount] {
			continue
		}
		if strings.HasPrefix(mount, "/etc/") || strings.HasPrefix(mount, "/proc") || strings.HasPrefix(mount, "/sys") {
			continue
		}
		seenMounts[mount] = true

		// Use real non-root effective capacity ratio used/(used+avail) matching df Capacity%
		// so ext4 5% root-reserved blocks never mask a 100%-full partition!
		effectiveCapKB := usedKB + availKB
		var usedPct float64
		if effectiveCapKB > 0 && availKB >= 0 {
			usedPct = roundOne(usedKB * 100.0 / effectiveCapKB)
		} else {
			usedPct = roundOne(usedKB * 100.0 / totalKB)
		}
		usedPct = math.Min(100, math.Max(0, usedPct))
		inodePct := math.Min(100, math.Max(0, inodeByMount[mount]))

		part := vault.DiskPartitionStat{
			MountPoint:   mount,
			Device:       dev,
			FSType:       fsType,
			TotalGB:      roundOne(totalKB / 1024.0 / 1024.0),
			UsedGB:       roundOne(usedKB / 1024.0 / 1024.0),
			AvailGB:      roundOne(availKB / 1024.0 / 1024.0),
			UsedPercent:  usedPct,
			InodePercent: inodePct,
		}
		snap.Disks = append(snap.Disks, part)

		if mount == "/" || snap.DiskTotalGB == 0 {
			snap.DiskTotalGB = part.TotalGB
			snap.DiskUsedGB = part.UsedGB
			snap.DiskPercent = part.UsedPercent
		}
		if usedPct >= snap.MaxPartPercent {
			snap.MaxPartPercent = usedPct
			snap.MaxPartMount = mount
		}
		if inodePct >= snap.MaxInodePercent {
			snap.MaxInodePercent = inodePct
			snap.MaxInodeMount = mount
		}
	}

	for _, l := range sections["MOUNTS"] {
		if strings.HasPrefix(l, "RO_MNT=") {
			p := strings.SplitN(strings.TrimPrefix(l, "RO_MNT="), "|", 2)
			if len(p) >= 1 && p[0] != "" {
				desc := p[0]
				if len(p) == 2 && p[1] != "" {
					desc = fmt.Sprintf("%s (%s)", p[0], p[1])
				}
				if !slices.Contains(snap.ReadOnlyMounts, desc) {
					snap.ReadOnlyMounts = append(snap.ReadOnlyMounts, desc)
				}
			}
		} else if strings.HasPrefix(l, "REMOTE_MNT=") {
			p := strings.SplitN(strings.TrimPrefix(l, "REMOTE_MNT="), "|", 2)
			if len(p) >= 1 && p[0] != "" {
				desc := p[0]
				if len(p) == 2 && p[1] != "" {
					desc = fmt.Sprintf("%s (%s)", p[0], p[1])
				}
				if !slices.Contains(snap.RemoteMounts, desc) {
					snap.RemoteMounts = append(snap.RemoteMounts, desc)
				}
			}
		}
	}

	// Disk Block I/O Rates (prefer sustained cross-interval delta, else T0->T1)
	rd0, wr0, io0 := sumBlockDevices(t0.bioByDev)
	rd1, wr1, io1 := sumBlockDevices(latest.bioByDev)
	snap.DiskTotalReadB = rd1
	snap.DiskTotalWriteB = wr1
	snap.DiskTotalIOOps = io1

	if prevElapsed > 0 && prev != nil && rd1 >= prev.DiskTotalReadB && wr1 >= prev.DiskTotalWriteB && prev.DiskTotalReadB+prev.DiskTotalWriteB > 0 {
		snap.DiskReadBps = int64(float64(rd1-prev.DiskTotalReadB) / prevElapsed)
		snap.DiskWriteBps = int64(float64(wr1-prev.DiskTotalWriteB) / prevElapsed)
		if io1 >= prev.DiskTotalIOOps {
			snap.DiskIOPS = int64(float64(io1-prev.DiskTotalIOOps) / prevElapsed)
		}
	} else if hasT1 && dt > 0 {
		if rd1 >= rd0 {
			snap.DiskReadBps = int64(float64(rd1-rd0) / dt)
		}
		if wr1 >= wr0 {
			snap.DiskWriteBps = int64(float64(wr1-wr0) / dt)
		}
		if io1 >= io0 {
			snap.DiskIOPS = int64(float64(io1-io0) / dt)
		}
	}

	// 5. Network Interfaces & Socket State Matrix
	ipByDev := make(map[string]string)
	operByDev := make(map[string]string)
	for _, l := range sections["IFACE"] {
		if strings.HasPrefix(l, "IP4=") {
			p := strings.SplitN(strings.TrimPrefix(l, "IP4="), "|", 2)
			if len(p) == 2 && ipByDev[p[0]] == "" {
				ipByDev[p[0]] = p[1]
			}
		} else if strings.HasPrefix(l, "OPER=") {
			p := strings.SplitN(strings.TrimPrefix(l, "OPER="), "|", 2)
			if len(p) == 2 {
				operByDev[p[0]] = p[1]
			}
		}
	}

	prevNICMap := make(map[string]vault.NetInterfaceStat)
	if prev != nil {
		for _, nic := range prev.Interfaces {
			prevNICMap[nic.Name] = nic
		}
	}

	devNames := make([]string, 0, len(latest.netByDev))
	for name := range latest.netByDev {
		if name == "lo" || name == "lo0" || strings.HasPrefix(name, "veth") {
			continue
		}
		devNames = append(devNames, name)
	}
	sort.Strings(devNames)

	for _, name := range devNames {
		cur := latest.netByDev[name]
		var rxBps, txBps int64
		computedFromPrev := false
		if prevElapsed > 0 {
			if pNic, ok := prevNICMap[name]; ok && cur.rxBytes >= pNic.RxBytes && cur.txBytes >= pNic.TxBytes {
				rxBps = int64(float64(cur.rxBytes-pNic.RxBytes) / prevElapsed)
				txBps = int64(float64(cur.txBytes-pNic.TxBytes) / prevElapsed)
				computedFromPrev = true
			}
		}
		if !computedFromPrev && hasT1 && dt > 0 {
			if n0, ok := t0.netByDev[name]; ok {
				if cur.rxBytes >= n0.rxBytes {
					rxBps = int64(float64(cur.rxBytes-n0.rxBytes) / dt)
				}
				if cur.txBytes >= n0.txBytes {
					txBps = int64(float64(cur.txBytes-n0.txBytes) / dt)
				}
			}
		}

		nicStat := vault.NetInterfaceStat{
			Name:      name,
			IPv4:      ipByDev[name],
			State:     operByDev[name],
			RxBytes:   cur.rxBytes,
			TxBytes:   cur.txBytes,
			RxBps:     rxBps,
			TxBps:     txBps,
			RxPackets: cur.rxPkts,
			TxPackets: cur.txPkts,
			RxErrors:  cur.rxErrs,
			TxErrors:  cur.txErrs,
			RxDrops:   cur.rxDrops,
			TxDrops:   cur.txDrops,
		}
		snap.Interfaces = append(snap.Interfaces, nicStat)

		if isCountedNIC(name) {
			snap.NetRxBps += rxBps
			snap.NetTxBps += txBps
			snap.NetRxTotalBytes += cur.rxBytes
			snap.NetTxTotalBytes += cur.txBytes
			snap.NetPacketErrors += cur.rxErrs + cur.txErrs + cur.rxDrops + cur.txDrops
		}
	}

	for _, l := range sections["SOCK"] {
		idx := strings.IndexByte(l, '=')
		if idx <= 0 {
			continue
		}
		k, v := l[:idx], l[idx+1:]
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			continue
		}
		switch k {
		case "TCP_01":
			snap.TCPEstablished += n
		case "TCP_03":
			snap.TCPSynRecv += n
		case "TCP_06":
			snap.TCPTimeWait += n
		case "TCP_08":
			snap.TCPCloseWait += n
		case "TCP_0A":
			snap.TCPListen += n
		case "UDP_ALL":
			snap.UDPSockets = n
		}
	}

	// 6. Processes & Top Resource Consumers
	parseProcRow := func(val string) (vault.ProcessStat, bool) {
		p := strings.SplitN(val, "|", 8)
		if len(p) < 8 {
			return vault.ProcessStat{}, false
		}
		pid, err := strconv.Atoi(strings.TrimSpace(p[0]))
		if err != nil || pid <= 0 {
			return vault.ProcessStat{}, false
		}
		cpuPct, _ := strconv.ParseFloat(strings.TrimSpace(p[2]), 64)
		memPct, _ := strconv.ParseFloat(strings.TrimSpace(p[3]), 64)
		rssKB, _ := strconv.ParseFloat(strings.TrimSpace(p[4]), 64)
		return vault.ProcessStat{
			PID:        pid,
			User:       strings.TrimSpace(p[1]),
			CPUPercent: roundOne(cpuPct),
			MemPercent: roundOne(memPct),
			RSSMB:      roundOne(rssKB / 1024.0),
			State:      strings.TrimSpace(p[5]),
			Elapsed:    strings.TrimSpace(p[6]),
			Command:    strings.TrimSpace(p[7]),
		}, true
	}

	for _, l := range sections["PROC"] {
		if strings.HasPrefix(l, "PSTAT=") {
			f := strings.Fields(strings.TrimPrefix(l, "PSTAT="))
			if len(f) >= 5 {
				snap.ProcsTotal, _ = strconv.Atoi(f[0])
				snap.ProcsRunning, _ = strconv.Atoi(f[1])
				snap.ProcsSleeping, _ = strconv.Atoi(f[2])
				snap.ProcsZombie, _ = strconv.Atoi(f[3])
				snap.ProcsBlocked, _ = strconv.Atoi(f[4])
			}
		} else if strings.HasPrefix(l, "TOP_CPU=") {
			if pr, ok := parseProcRow(strings.TrimPrefix(l, "TOP_CPU=")); ok {
				snap.TopCPUProcs = append(snap.TopCPUProcs, pr)
			}
		} else if strings.HasPrefix(l, "TOP_MEM=") {
			if pr, ok := parseProcRow(strings.TrimPrefix(l, "TOP_MEM=")); ok {
				snap.TopMemProcs = append(snap.TopMemProcs, pr)
			}
		}
	}

	// 7. Listening Ports (with truncation flag)
	seenPorts := make(map[string]bool)
	for _, l := range sections["PORTS"] {
		if l == "PORTS_TRUNC=1" {
			snap.PortsTruncated = true
			continue
		}
		if ps, ok := parseListeningPortLine(l); ok {
			dedup := fmt.Sprintf("%s|%s|%d", ps.Proto, ps.BindAddr, ps.Port)
			if !seenPorts[dedup] {
				seenPorts[dedup] = true
				snap.ListeningPorts = append(snap.ListeningPorts, ps)
			}
		}
	}
	sort.Slice(snap.ListeningPorts, func(i, j int) bool {
		if snap.ListeningPorts[i].Port != snap.ListeningPorts[j].Port {
			return snap.ListeningPorts[i].Port < snap.ListeningPorts[j].Port
		}
		return snap.ListeningPorts[i].Proto < snap.ListeningPorts[j].Proto
	})

	// 8. Systemd & Services
	for _, l := range sections["SYSTEMD"] {
		if strings.HasPrefix(l, "FAILED_UNIT=") {
			u := strings.TrimSpace(strings.TrimPrefix(l, "FAILED_UNIT="))
			u = strings.TrimPrefix(u, "●")
			u = strings.TrimSpace(u)
			if u != "" {
				snap.SystemdFailedUnits = append(snap.SystemdFailedUnits, u)
			}
		} else if strings.HasPrefix(l, "SVC=") {
			p := strings.SplitN(strings.TrimPrefix(l, "SVC="), "|", 3)
			if len(p) >= 2 {
				snap.Services = append(snap.Services, vault.ServiceStat{
					Name:    strings.TrimSpace(p[0]),
					State:   strings.TrimSpace(p[1]),
					Watched: len(p) >= 3 && p[2] == "watched",
				})
			}
		}
	}
	snap.SystemdFailedCount = len(snap.SystemdFailedUnits)

	// 9. Docker Containers (including DaemonDown & Exited non-zero)
	for _, l := range sections["DOCKER"] {
		switch {
		case l == "DOCKER_BIN=1":
			snap.Docker.Installed = true
		case l == "DOCKER_OK=1":
			snap.Docker.Installed = true
			snap.Docker.DaemonDown = false
		case l == "DOCKER_DOWN=1":
			snap.Docker.Installed = true
			snap.Docker.DaemonDown = true
		case l == "DOCKER_TRUNC=1":
			snap.Docker.Truncated = true
		case strings.HasPrefix(l, "CTR="):
			snap.Docker.Installed = true
			p := strings.SplitN(strings.TrimPrefix(l, "CTR="), "|", 5)
			if len(p) >= 5 {
				idShort := p[0]
				if len(idShort) > 12 {
					idShort = idShort[:12]
				}
				state := strings.ToLower(strings.TrimSpace(p[3]))
				status := strings.TrimSpace(p[4])
				health := ""
				lowStatus := strings.ToLower(status)
				if strings.Contains(lowStatus, "(unhealthy)") {
					health = "unhealthy"
				} else if strings.Contains(lowStatus, "(healthy)") {
					health = "healthy"
				}
				switch state {
				case "running":
					snap.Docker.Running++
				default:
					snap.Docker.Stopped++
				}
				if health == "unhealthy" || state == "restarting" || state == "dead" {
					snap.Docker.Unhealthy++
				} else if state == "exited" && strings.Contains(lowStatus, "exited (") && !strings.Contains(lowStatus, "exited (0)") {
					snap.Docker.ExitedAbnormal++
				}
				snap.Docker.Containers = append(snap.Docker.Containers, vault.ContainerStat{
					ID:     idShort,
					Name:   strings.TrimSpace(p[1]),
					Image:  strings.TrimSpace(p[2]),
					State:  state,
					Status: status,
					Health: health,
				})
			}
		}
	}

	// 10. L2 Hardware & Kernel Errors (RAID + dmesg/journalctl -k)
	for _, l := range sections["HW"] {
		switch {
		case strings.HasPrefix(l, "RAID_BAD="):
			v := strings.TrimSpace(strings.TrimPrefix(l, "RAID_BAD="))
			if v != "" && !slices.Contains(snap.RAIDDegraded, v) {
				snap.RAIDDegraded = append(snap.RAIDDegraded, v)
			}
		case strings.HasPrefix(l, "KERR_CNT="):
			snap.KernelErrorCount, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(l, "KERR_CNT=")))
		case strings.HasPrefix(l, "KERR="):
			v := strings.TrimSpace(strings.TrimPrefix(l, "KERR="))
			if v != "" {
				snap.KernelErrors = append(snap.KernelErrors, v)
			}
		}
	}
	if snap.KernelErrorCount == 0 && len(snap.KernelErrors) > 0 {
		snap.KernelErrorCount = len(snap.KernelErrors)
	}

	// 11. Security Posture & SSH Login Telemetry
	snap.Security.FirewallStatus = "unknown"
	for _, l := range sections["SEC"] {
		switch {
		case strings.HasPrefix(l, "WHO="):
			p := strings.SplitN(strings.TrimPrefix(l, "WHO="), "|", 4)
			if len(p) >= 3 {
				from := ""
				if len(p) == 4 {
					from = strings.Trim(strings.TrimSpace(p[3]), "()")
				}
				snap.Security.ActiveUsers = append(snap.Security.ActiveUsers, vault.LoggedInUserStat{
					User:      strings.TrimSpace(p[0]),
					TTY:       strings.TrimSpace(p[1]),
					LoginTime: strings.TrimSpace(p[2]),
					FromIP:    from,
				})
			}
		case strings.HasPrefix(l, "UID0="):
			u := strings.TrimSpace(strings.TrimPrefix(l, "UID0="))
			if u != "" && !slices.Contains(snap.Security.UIDZeroUsers, u) {
				snap.Security.UIDZeroUsers = append(snap.Security.UIDZeroUsers, u)
			}
		case strings.HasPrefix(l, "REBOOT_REQ="):
			snap.Security.RebootRequired = strings.TrimPrefix(l, "REBOOT_REQ=") == "1"
		case strings.HasPrefix(l, "FW="):
			p := strings.SplitN(strings.TrimPrefix(l, "FW="), "|", 2)
			if len(p) >= 1 && p[0] != "" {
				snap.Security.FirewallStatus = p[0]
			}
			if len(p) == 2 {
				snap.Security.FirewallDetail = p[1]
			}
		case strings.HasPrefix(l, "MAC="):
			snap.Security.MACFramework = strings.TrimSpace(strings.TrimPrefix(l, "MAC="))
		case strings.HasPrefix(l, "SSH_FAIL_CNT="):
			snap.Security.SSHFailedRecent, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(l, "SSH_FAIL_CNT=")))
		case strings.HasPrefix(l, "SSH_FAIL_IP="):
			ip := strings.TrimSpace(strings.TrimPrefix(l, "SSH_FAIL_IP="))
			if ip != "" {
				snap.Security.TopFailedIPs = append(snap.Security.TopFailedIPs, ip)
			}
		case strings.HasPrefix(l, "SSH_LOGIN="):
			p := strings.SplitN(strings.TrimPrefix(l, "SSH_LOGIN="), "|", 4)
			if len(p) >= 2 && strings.TrimSpace(p[1]) != "" {
				ev := vault.SSHLoginEvent{
					User:   strings.TrimSpace(p[0]),
					FromIP: strings.TrimSpace(p[1]),
				}
				if len(p) >= 3 {
					ev.Method = strings.TrimSpace(p[2])
				}
				if len(p) >= 4 {
					ev.Timestamp = strings.TrimSpace(p[3])
				}
				snap.Security.RecentSSHLogins = append(snap.Security.RecentSSHLogins, ev)
			}
		}
	}

	// 12. L3 Zero-AI Deep Security (FIM, Persistence, Suspicious Procs, High-Risk Outbound, Weak SSH Config)
	for _, l := range sections["SEC_DEEP"] {
		switch {
		case strings.HasPrefix(l, "FIM="):
			p := strings.SplitN(strings.TrimPrefix(l, "FIM="), "|", 2)
			if len(p) == 2 && p[0] != "" && p[1] != "" {
				if snap.Security.FileHashes == nil {
					snap.Security.FileHashes = make(map[string]string)
				}
				snap.Security.FileHashes[strings.TrimSpace(p[0])] = strings.TrimSpace(p[1])
			}
		case strings.HasPrefix(l, "PERSIST_HASH="):
			snap.Security.PersistenceHash = strings.TrimSpace(strings.TrimPrefix(l, "PERSIST_HASH="))
		case strings.HasPrefix(l, "SUSP_PROC="):
			p := strings.SplitN(strings.TrimPrefix(l, "SUSP_PROC="), "|", 6)
			if len(p) >= 5 {
				pid, _ := strconv.Atoi(strings.TrimSpace(p[0]))
				sp := vault.SuspiciousProcStat{
					PID:      pid,
					User:     strings.TrimSpace(p[1]),
					Reason:   strings.TrimSpace(p[2]),
					Severity: strings.TrimSpace(p[3]),
					Command:  strings.TrimSpace(p[4]),
				}
				if len(p) == 6 {
					sp.ExePath = strings.TrimSpace(p[5])
				}
				snap.Security.SuspiciousProcs = append(snap.Security.SuspiciousProcs, sp)
			}
		case strings.HasPrefix(l, "OUTB="):
			p := strings.SplitN(strings.TrimPrefix(l, "OUTB="), "|", 5)
			if len(p) >= 4 {
				port, _ := strconv.Atoi(strings.TrimSpace(p[1]))
				pid, _ := strconv.Atoi(strings.TrimSpace(p[2]))
				oc := vault.OutboundConnStat{
					RemoteIP:   strings.TrimSpace(p[0]),
					RemotePort: port,
					PID:        pid,
					Process:    strings.TrimSpace(p[3]),
				}
				if len(p) == 5 {
					oc.Reason = strings.TrimSpace(p[4])
				}
				snap.Security.SuspiciousOutbound = append(snap.Security.SuspiciousOutbound, oc)
			}
		case strings.HasPrefix(l, "SSH_WEAK="):
			v := strings.TrimSpace(strings.TrimPrefix(l, "SSH_WEAK="))
			if v != "" && !slices.Contains(snap.Security.SSHWeakConfigs, v) {
				snap.Security.SSHWeakConfigs = append(snap.Security.SSHWeakConfigs, v)
			}
		}
	}
}
