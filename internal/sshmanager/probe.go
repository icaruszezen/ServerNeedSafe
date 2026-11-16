package sshmanager

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ServerProbeResult holds handshake latency and agentless remote system metrics.
type ServerProbeResult struct {
	ServerID    string  `json:"server_id"`
	ServerName  string  `json:"server_name"`
	Reachable   bool    `json:"reachable"`
	LatencyMs   int64   `json:"latency_ms"`
	Fingerprint string  `json:"fingerprint,omitempty"`
	Hostname    string  `json:"hostname,omitempty"`
	OS          string  `json:"os,omitempty"`
	Kernel      string  `json:"kernel,omitempty"`
	Arch        string  `json:"arch,omitempty"`
	Uptime      string  `json:"uptime,omitempty"`
	CPUCores    int     `json:"cpu_cores,omitempty"`
	LoadAvg     string  `json:"load_avg,omitempty"`
	MemUsedMB   int64   `json:"mem_used_mb,omitempty"`
	MemTotalMB  int64   `json:"mem_total_mb,omitempty"`
	MemPercent  float64 `json:"mem_percent,omitempty"`
	DiskUsedGB  float64 `json:"disk_used_gb,omitempty"`
	DiskTotalGB float64 `json:"disk_total_gb,omitempty"`
	DiskPercent float64 `json:"disk_percent,omitempty"`
}

const telemetryShellScript = `
printf "HOSTNAME=%s\n" "$(hostname 2>/dev/null || uname -n)"
OS_NAME=""
if [ -r /etc/os-release ]; then
  OS_NAME=$(. /etc/os-release && printf "%s" "${PRETTY_NAME:-$NAME}")
fi
[ -z "$OS_NAME" ] && OS_NAME=$(uname -s)
printf "OS=%s\n" "$OS_NAME"
printf "KERNEL=%s\n" "$(uname -r 2>/dev/null)"
printf "ARCH=%s\n" "$(uname -m 2>/dev/null)"
printf "CORES=%s\n" "$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1)"
if [ -r /proc/loadavg ]; then
  awk '{printf "LOAD=%s / %s / %s\n", $1, $2, $3}' /proc/loadavg
fi
if [ -r /proc/uptime ]; then
  awk '{sec=int($1); d=int(sec/86400); h=int((sec%86400)/3600); m=int((sec%3600)/60); if(d>0) printf "UPTIME=%dd %dh %dm\n",d,h,m; else printf "UPTIME=%dh %dm\n",h,m}' /proc/uptime
fi
if [ -r /proc/meminfo ]; then
  awk '/^MemTotal:/ {t=$2} /^MemAvailable:/ {a=$2} END {if(t>0){u=t-a; printf "MEM_KB=%d %d\n", u, t}}' /proc/meminfo
fi
(df -Pk . 2>/dev/null || df -Pk / 2>/dev/null) | awk 'NR==2 && NF>=5 {printf "DISK_KB=%s %s\n", $(NF-3), $(NF-4)}'
`

// ProbeServer tests SSH connectivity, verifies host key, and collects live system telemetry.
func (m *Manager) ProbeServer(serverID, trustFingerprint, clientIP string) (*ServerProbeResult, error) {
	start := time.Now()
	client, err := m.Dial(serverID, DialOptions{
		TrustFingerprint: trustFingerprint,
		ClientIP:         clientIP,
		Timeout:          10 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	defer client.Close()

	latencyMs := time.Since(start).Milliseconds()
	if latencyMs <= 0 {
		latencyMs = 1
	}

	res := &ServerProbeResult{
		ServerID:    serverID,
		ServerName:  client.Server.Name,
		Reachable:   true,
		LatencyMs:   latencyMs,
		Fingerprint: client.Fingerprint,
	}

	sess, err := client.NewSession()
	if err == nil {
		defer sess.Close()
		out, cmdErr := runSessionWithTimeout(sess, telemetryShellScript, 6*time.Second)
		if cmdErr == nil {
			parseTelemetryOutput(out, res)
		}
	}

	osLabel := strings.TrimSpace(res.OS)
	if osLabel == "" && res.Kernel != "" {
		osLabel = "Linux " + res.Kernel
	}
	m.store.UpdateServerRuntimeMeta(serverID, latencyMs, osLabel, false)
	return res, nil
}

func parseTelemetryOutput(raw string, res *ServerProbeResult) {
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		k := line[:idx]
		v := strings.TrimSpace(line[idx+1:])
		switch k {
		case "HOSTNAME":
			res.Hostname = v
		case "OS":
			res.OS = v
		case "KERNEL":
			res.Kernel = v
		case "ARCH":
			res.Arch = v
		case "CORES":
			if n, err := strconv.Atoi(v); err == nil {
				res.CPUCores = n
			}
		case "LOAD":
			res.LoadAvg = v
		case "UPTIME":
			res.Uptime = v
		case "MEM_KB":
			parts := strings.Fields(v)
			if len(parts) == 2 {
				usedKB, e1 := strconv.ParseInt(parts[0], 10, 64)
				totalKB, e2 := strconv.ParseInt(parts[1], 10, 64)
				if e1 == nil && e2 == nil && totalKB > 0 {
					res.MemUsedMB = usedKB / 1024
					res.MemTotalMB = totalKB / 1024
					res.MemPercent = float64(int(float64(usedKB)*1000/float64(totalKB))) / 10.0
				}
			}
		case "DISK_KB":
			parts := strings.Fields(v)
			if len(parts) == 2 {
				usedKB, e1 := strconv.ParseFloat(parts[0], 64)
				totalKB, e2 := strconv.ParseFloat(parts[1], 64)
				if e1 == nil && e2 == nil && totalKB > 0 {
					res.DiskUsedGB = float64(int(usedKB/1024/1024*10)) / 10.0
					res.DiskTotalGB = float64(int(totalKB/1024/1024*10)) / 10.0
					res.DiskPercent = float64(int(usedKB*1000/totalKB)) / 10.0
				}
			}
		}
	}
}

type sessionRunner interface {
	Run(cmd string) error
	Close() error
}

func runSessionWithTimeout(sess interface {
	CombinedOutput(string) ([]byte, error)
	Close() error
}, cmd string, timeout time.Duration) (string, error) {
	type outPair struct {
		b   []byte
		err error
	}
	ch := make(chan outPair, 1)
	go func() {
		b, err := sess.CombinedOutput(cmd)
		ch <- outPair{b: b, err: err}
	}()
	select {
	case r := <-ch:
		return string(r.b), r.err
	case <-time.After(timeout):
		_ = sess.Close()
		return "", context.DeadlineExceeded
	}
}

// BatchExecResult captures command execution result for one server in a batch run.
type BatchExecResult struct {
	ServerID   string `json:"server_id"`
	ServerName string `json:"server_name"`
	Host       string `json:"host"`
	Success    bool   `json:"success"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMs int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

// BatchExecute runs command concurrently across serverIDs with bounded concurrency.
func (m *Manager) BatchExecute(serverIDs []string, command string, timeout time.Duration, clientIP string) []BatchExecResult {
	if timeout <= 0 || timeout > 2*time.Minute {
		timeout = 25 * time.Second
	}
	results := make([]BatchExecResult, len(serverIDs))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup

	for idx, sid := range serverIDs {
		wg.Add(1)
		go func(i int, serverID string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			start := time.Now()
			res := BatchExecResult{ServerID: serverID}
			if srv, err := m.store.GetServerSecret(serverID); err == nil {
				res.ServerName = srv.Name
				res.Host = fmt.Sprintf("%s:%d", srv.Host, srv.Port)
			}

			client, err := m.Dial(serverID, DialOptions{
				ClientIP: clientIP,
				Timeout:  10 * time.Second,
			})
			if err != nil {
				res.Error = err.Error()
				res.DurationMs = time.Since(start).Milliseconds()
				results[i] = res
				return
			}
			defer client.Close()

			sess, err := client.NewSession()
			if err != nil {
				res.Error = err.Error()
				res.DurationMs = time.Since(start).Milliseconds()
				results[i] = res
				return
			}
			defer sess.Close()

			var stdoutBuf, stderrBuf bytes.Buffer
			sess.Stdout = &stdoutBuf
			sess.Stderr = &stderrBuf

			done := make(chan error, 1)
			go func() {
				done <- sess.Run(command)
			}()

			select {
			case runErr := <-done:
				res.Stdout = stdoutBuf.String()
				res.Stderr = stderrBuf.String()
				if runErr != nil {
					res.Error = runErr.Error()
					res.ExitCode = 1
				} else {
					res.Success = true
					res.ExitCode = 0
				}
			case <-time.After(timeout):
				_ = sess.Close()
				res.Stdout = stdoutBuf.String()
				res.Stderr = stderrBuf.String()
				res.Error = "命令执行超时"
				res.ExitCode = 124
			}
			res.DurationMs = time.Since(start).Milliseconds()
			results[i] = res
		}(idx, sid)
	}
	wg.Wait()

	m.store.RecordAudit("ssh.batch_exec", fmt.Sprintf("%d 台服务器", len(serverIDs)), fmt.Sprintf("批量执行运维指令: %.60s", command), clientIP, true)
	return results
}
