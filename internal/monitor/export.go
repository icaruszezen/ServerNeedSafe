package monitor

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

// ParseHistoryRange converts a shorthand duration string ("15m", "1h", "6h", "24h", "7d", "all") to time.Duration.
func ParseHistoryRange(q string) time.Duration {
	switch strings.ToLower(strings.TrimSpace(q)) {
	case "15m":
		return 15 * time.Minute
	case "30m":
		return 30 * time.Minute
	case "1h", "":
		return time.Hour
	case "6h":
		return 6 * time.Hour
	case "12h":
		return 12 * time.Hour
	case "24h", "1d":
		return 24 * time.Hour
	case "7d":
		return 7 * 24 * time.Hour
	case "all", "0":
		return 0
	default:
		if d, err := time.ParseDuration(q); err == nil && d >= 0 {
			return d
		}
		return time.Hour
	}
}

// ExportHistory formats historical monitoring series and overview data as UTF-8 CSV (with BOM) or JSON entirely client-side.
func ExportHistory(store *vault.Store, format, serverID, rangeQuery, clientIP string) ([]byte, string, string, error) {
	if store == nil {
		return nil, "", "", vault.ErrVaultLocked
	}
	fmtClean := strings.ToLower(strings.TrimSpace(format))
	if fmtClean != "csv" {
		fmtClean = "json"
	}
	sid := strings.TrimSpace(serverID)
	rangeDur := ParseHistoryRange(rangeQuery)
	if strings.TrimSpace(rangeQuery) == "" {
		rangeDur = 0 // export full retained series by default
	}

	var details []*vault.ServerMonitorDetail
	if sid != "" {
		d, err := store.GetServerMonitorDetail(sid, rangeDur)
		if err != nil {
			return nil, "", "", err
		}
		details = append(details, d)
	} else {
		servers, err := store.ListServers()
		if err != nil {
			return nil, "", "", err
		}
		for _, srv := range servers {
			if d, dErr := store.GetServerMonitorDetail(srv.ID, rangeDur); dErr == nil {
				details = append(details, d)
			}
		}
	}

	tsSuffix := time.Now().Format("20060102-150405")
	store.RecordAudit("monitor.export", fmtClean, fmt.Sprintf("导出监控历史记录 (%d 台节点)", len(details)), clientIP, true)

	if fmtClean == "csv" {
		var buf bytes.Buffer
		// UTF-8 BOM for Excel compatibility with CJK server names
		buf.Write([]byte{0xEF, 0xBB, 0xBF})
		cw := csv.NewWriter(&buf)
		_ = cw.Write([]string{
			"timestamp", "server_id", "server_name", "host", "reachable", "health_score",
			"latency_ms", "cpu_pct", "cpu_user_pct", "cpu_sys_pct", "cpu_iowait_pct",
			"load_1", "load_5", "load_15", "mem_pct", "mem_used_mb", "swap_pct",
			"disk_pct", "inode_pct", "disk_read_bps", "disk_write_bps", "disk_iops",
			"net_rx_bps", "net_tx_bps", "tcp_established", "tcp_time_wait", "tcp_close_wait",
			"procs_total", "procs_running", "procs_zombie", "fd_pct", "cpu_temp_c", "ssh_failed_recent",
		})
		for _, d := range details {
			hostPort := fmt.Sprintf("%s:%d", d.Server.Host, d.Server.Port)
			for _, pt := range d.Series {
				_ = cw.Write([]string{
					pt.Timestamp.Format(time.RFC3339),
					d.Server.ID,
					d.Server.Name,
					hostPort,
					strconv.FormatBool(pt.Reachable),
					strconv.Itoa(pt.HealthScore),
					strconv.FormatInt(pt.LatencyMs, 10),
					fmt.Sprintf("%.1f", pt.CPUPercent),
					fmt.Sprintf("%.1f", pt.CPUUserPct),
					fmt.Sprintf("%.1f", pt.CPUSystemPct),
					fmt.Sprintf("%.1f", pt.CPUIowaitPct),
					fmt.Sprintf("%.2f", pt.Load1),
					fmt.Sprintf("%.2f", pt.Load5),
					fmt.Sprintf("%.2f", pt.Load15),
					fmt.Sprintf("%.1f", pt.MemPercent),
					strconv.FormatInt(pt.MemUsedMB, 10),
					fmt.Sprintf("%.1f", pt.SwapPercent),
					fmt.Sprintf("%.1f", pt.DiskPercent),
					fmt.Sprintf("%.1f", pt.InodePercent),
					strconv.FormatInt(pt.DiskReadBps, 10),
					strconv.FormatInt(pt.DiskWriteBps, 10),
					strconv.FormatInt(pt.DiskIOPS, 10),
					strconv.FormatInt(pt.NetRxBps, 10),
					strconv.FormatInt(pt.NetTxBps, 10),
					strconv.Itoa(pt.TCPEstablished),
					strconv.Itoa(pt.TCPTimeWait),
					strconv.Itoa(pt.TCPCloseWait),
					strconv.Itoa(pt.ProcsTotal),
					strconv.Itoa(pt.ProcsRunning),
					strconv.Itoa(pt.ProcsZombie),
					fmt.Sprintf("%.1f", pt.FDPercent),
					fmt.Sprintf("%.1f", pt.CPUTempC),
					strconv.Itoa(pt.SSHFailedRecent),
				})
			}
		}
		cw.Flush()
		filename := fmt.Sprintf("ServerNeedSafe-monitor-%s.csv", tsSuffix)
		return buf.Bytes(), filename, "text/csv; charset=utf-8", nil
	}

	overview, _ := store.GetMonitorOverview()
	payload := map[string]any{
		"exported_at": time.Now().UTC().Format(time.RFC3339),
		"overview":    overview,
		"servers":     details,
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, "", "", err
	}
	filename := fmt.Sprintf("ServerNeedSafe-monitor-%s.json", tsSuffix)
	return raw, filename, "application/json; charset=utf-8", nil
}
