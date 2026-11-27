package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/api"
	"github.com/icaruszezen/ServerNeedSafe/internal/auth"
	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type ptyRecorder struct {
	mu         sync.Mutex
	rawBytes   []byte
	ctrlCCount int
	ctrlDCount int
	ctrlLCount int
	escCount   int
	tabCount   int
}

func (r *ptyRecorder) record(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.rawBytes) < 16384 {
		r.rawBytes = append(r.rawBytes, p...)
	}
	for _, b := range p {
		switch b {
		case 0x03:
			r.ctrlCCount++
		case 0x04:
			r.ctrlDCount++
		case 0x0c:
			r.ctrlLCount++
		case 0x1b:
			r.escCount++
		case '\t':
			r.tabCount++
		}
	}
}

func (r *ptyRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rawBytes = nil
	r.ctrlCCount = 0
	r.ctrlDCount = 0
	r.ctrlLCount = 0
	r.escCount = 0
	r.tabCount = 0
}

func (r *ptyRecorder) snapshot() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return map[string]any{
		"ctrl_c_count": r.ctrlCCount,
		"ctrl_d_count": r.ctrlDCount,
		"ctrl_l_count": r.ctrlLCount,
		"esc_count":    r.escCount,
		"tab_count":    r.tabCount,
		"raw_hex":      hex.EncodeToString(r.rawBytes),
		"raw_text":     string(r.rawBytes),
	}
}

type mockHostProfile struct {
	hostname   string
	osPretty   string
	kernel     string
	cores      int
	cpuModel   string
	highStress bool
}

func buildDynamicTelemetry(prof mockHostProfile, tick int64) string {
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	mod := int(tick % 6)

	if !prof.highStress {
		// Healthy Edge Gateway Node (~28% - 43% CPU, ~45% Mem, ~48% Disk)
		busyTicks := 28 + mod*3
		idleTicks := 100 - busyTicks
		rxDelta := 320000 + mod*65000
		txDelta := 480000 + mod*85000
		memAvail := 9011200 - mod*163840
		return fmt.Sprintf(`===SNS_SEC:SAMPLE_T0===
UP=248910.00
CPU=cpu  12000 120 4200 92000 410 30 60 80 0 0
CTXT=1840000
NET=eth0 842000000 620000 0 0 1260000000 840000 0 0
BIO=nvme0n1 14200 118000 26400 242000
===SNS_SEC:SYS===
HOSTNAME=%s
OS=%s
KERNEL=%s
ARCH=x86_64
CORES=%d
CPU_MODEL=%s
VIRT=kvm
UPTIME_SEC=248910
LOAD=%.2f %.2f %.2f 2/348
SERVER_TIME=%s
TIMEZONE=Asia/Shanghai
NTP=yes
TEMP_C=%.1f
===SNS_SEC:MEM===
MemTotal=16384000
MemFree=4194304
MemAvailable=%d
Buffers=614400
Cached=3891200
SReclaimable=409600
SwapTotal=4096000
SwapFree=3980000
FILE_NR=2880 131072
OOM_KILL=0
===SNS_SEC:DISK===
FS=/dev/nvme0n1p1|ext4|104857600|50331648|54525952|48%%|/
FS=/dev/nvme1n1|xfs|209715200|88080384|121634816|42%%|/srv/gateway
===SNS_SEC:INODE===
INODE=/|16%%
INODE=/srv/gateway|19%%
===SNS_SEC:IFACE===
IP4=eth0|10.16.4.12
OPER=eth0|up
===SNS_SEC:SOCK===
TCP_01=%d
TCP_03=6
TCP_06=42
TCP_08=3
TCP_0A=7
UDP_ALL=9
===SNS_SEC:PROC===
PSTAT=268 2 266 0 0
TOP_CPU=1120|www-data|18.4|6.8|1114112|S|48:12:09|nginx: worker process -c /etc/nginx/nginx.conf
TOP_CPU=1640|root|9.2|4.5|737280|S|68:41:22|envoy --config-path /etc/envoy/edge.yaml
TOP_MEM=1120|www-data|18.4|6.8|1114112|S|48:12:09|nginx: worker process -c /etc/nginx/nginx.conf
TOP_MEM=2048|redis|3.6|5.1|835584|S|68:40:10|redis-server 127.0.0.1:6379
===SNS_SEC:PORTS===
tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=782,fd=3))
tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=1118,fd=6))
tcp LISTEN 0 511 127.0.0.1:6379 0.0.0.0:* users:(("redis-server",pid=2048,fd=7))
===SNS_SEC:SYSTEMD===
SVC=nginx|active|watched
SVC=sshd|active|auto
SVC=docker|active|watched
SVC=fail2ban|active|auto
===SNS_SEC:DOCKER===
DOCKER_OK=1
CTR=7f91bc02a81d|edge-ingress-proxy|nginx:1.27-alpine|running|Up 2 days (healthy)
CTR=3a84de19f20b|acme-cert-renewer|certbot/certbot:v2.11|running|Up 2 days (healthy)
===SNS_SEC:SEC===
WHO=root|pts/0|2026-11-18 07:45|(10.16.0.5)
UID0=root
REBOOT_REQ=0
FW=active|ufw
MAC=AppArmor:Y
SSH_FAIL_CNT=3
SSH_FAIL_IP=198.51.100.24(3)
===SNS_SEC:SAMPLE_T1===
UP=248910.50
CPU=cpu  %d 120 %d %d %d 30 60 80 0 0
CTXT=%d
NET=eth0 %d 620420 0 0 %d 840580 0 0
BIO=nvme0n1 14218 118640 26436 243280
`,
			prof.hostname,
			prof.osPretty,
			prof.kernel,
			prof.cores,
			prof.cpuModel,
			1.45+float64(mod)*0.18,
			1.32+float64(mod)*0.12,
			1.18,
			now,
			48.5+float64(mod)*1.2,
			memAvail,
			186+mod*14,
			12000+(busyTicks*2/3),
			4200+(busyTicks-busyTicks*2/3-2),
			92000+idleTicks,
			410+2,
			1840000+920+mod*110,
			842000000+rxDelta,
			1260000000+txDelta,
		)
	}

	// High-Stress Database Node (~84% - 92% CPU, ~88% Mem, 91% Disk, SSH brute-force warning)
	busyTicks := 84 + mod*2
	if busyTicks > 95 {
		busyTicks = 95
	}
	idleTicks := 100 - busyTicks
	return fmt.Sprintf(`===SNS_SEC:SAMPLE_T0===
UP=614200.00
CPU=cpu  44000 200 14000 160000 6200 80 120 400 0 0
CTXT=9200000
NET=eth0 2450000000 1820000 0 0 3980000000 2410000 0 1
BIO=nvme0n1 88000 920000 164000 1840000
===SNS_SEC:SYS===
HOSTNAME=%s
OS=%s
KERNEL=%s
ARCH=x86_64
CORES=%d
CPU_MODEL=%s
VIRT=kvm
UPTIME_SEC=614200
LOAD=%.2f %.2f %.2f 7/642
SERVER_TIME=%s
TIMEZONE=Asia/Singapore
NTP=yes
TEMP_C=%.1f
===SNS_SEC:MEM===
MemTotal=32768000
MemFree=1420000
MemAvailable=%d
Buffers=512000
Cached=2048000
SReclaimable=256000
SwapTotal=8192000
SwapFree=2867200
FILE_NR=9420 262144
OOM_KILL=1
===SNS_SEC:DISK===
FS=/dev/nvme0n1p1|ext4|104857600|79691776|25165824|76%%|/
FS=/dev/nvme1n1|xfs|524288000|477102080|47185920|91%%|/var/lib/postgresql
===SNS_SEC:INODE===
INODE=/|28%%
INODE=/var/lib/postgresql|64%%
===SNS_SEC:IFACE===
IP4=eth0|10.28.12.20
OPER=eth0|up
===SNS_SEC:SOCK===
TCP_01=%d
TCP_03=24
TCP_06=118
TCP_08=46
TCP_0A=9
UDP_ALL=12
===SNS_SEC:PROC===
PSTAT=482 6 473 1 2
TOP_CPU=2410|postgres|246.8|48.2|15794176|R|92:18:44|postgres: 16/main: autovacuum worker orders_2026
TOP_CPU=2588|postgres|94.2|22.4|7340032|R|14:09:12|postgres: 16/main: walwriter
TOP_MEM=2410|postgres|246.8|48.2|15794176|R|92:18:44|postgres: 16/main: autovacuum worker orders_2026
===SNS_SEC:PORTS===
tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=690,fd=3))
tcp LISTEN 0 244 0.0.0.0:5432 0.0.0.0:* users:(("postgres",pid=2398,fd=5))
tcp LISTEN 0 511 0.0.0.0:9187 0.0.0.0:* users:(("postgres_export",pid=2910,fd=6))
===SNS_SEC:SYSTEMD===
FAILED_UNIT=● pg-wal-archive.service
SVC=postgresql|active|watched
SVC=pgbouncer|active|watched
SVC=pg-wal-archive|failed|watched
===SNS_SEC:DOCKER===
DOCKER_OK=1
CTR=8b22e014c9a1|pgbouncer-tx-pool|edoburu/pgbouncer:1.23|running|Up 7 days (healthy)
CTR=19fe73a08b12|prometheus-pg-exporter|quay.io/prometheuscommunity/postgres-exporter:v0.15|running|Up 3 hours (unhealthy)
===SNS_SEC:SEC===
WHO=dba_oncall|pts/1|2026-11-18 06:20|(10.28.0.9)
UID0=root
REBOOT_REQ=1
FW=active|nftables
MAC=AppArmor:Y
SSH_FAIL_CNT=58
SSH_FAIL_IP=203.0.113.77(41)
SSH_FAIL_IP=198.51.100.92(17)
===SNS_SEC:SAMPLE_T1===
UP=614200.50
CPU=cpu  %d 200 %d %d %d 80 120 %d 0 0
CTXT=9203800
NET=eth0 %d 1821900 0 0 %d 2412600 0 1
BIO=nvme0n1 88140 924800 164260 1851200
`,
		prof.hostname,
		prof.osPretty,
		prof.kernel,
		prof.cores,
		prof.cpuModel,
		9.80+float64(mod)*0.35,
		8.40+float64(mod)*0.22,
		6.95,
		now,
		72.4+float64(mod)*1.1,
		3932160-mod*98304,
		340+mod*18,
		44000+(busyTicks-24),
		14000+12,
		160000+idleTicks,
		6200+9,
		400+3,
		2450000000+920000+mod*140000,
		3980000000+1640000+mod*210000,
	)
}

func startEmbeddedSSHNode(
	expectedUser, expectedPass string,
	prof mockHostProfile,
	sftpHandlers sftp.Handlers,
	recorder *ptyRecorder,
	sampleCounter *atomic.Int64,
) (int, func(), error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return 0, nil, err
	}
	hostSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return 0, nil, err
	}

	acceptedDynamicKeys := &sync.Map{}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == expectedUser && string(pass) == expectedPass {
				return nil, nil
			}
			return nil, errors.New("invalid ssh credentials")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if _, ok := acceptedDynamicKeys.Load(string(key.Marshal())); ok {
				return nil, nil
			}
			return nil, errors.New("unregistered public key")
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, err
	}

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSSHConn(nc, cfg, prof, sftpHandlers, recorder, sampleCounter)
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	return port, func() { _ = ln.Close() }, nil
}

func handleSSHConn(
	nc net.Conn,
	cfg *ssh.ServerConfig,
	prof mockHostProfile,
	sftpHandlers sftp.Handlers,
	recorder *ptyRecorder,
	sampleCounter *atomic.Int64,
) {
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		_ = nc.Close()
		return
	}
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			continue
		}
		go func(in <-chan *ssh.Request) {
			shellStarted := false
			for req := range in {
				switch req.Type {
				case "pty-req", "window-change", "env":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
				case "subsystem":
					var sub struct{ Name string }
					_ = ssh.Unmarshal(req.Payload, &sub)
					if sub.Name == "sftp" {
						if req.WantReply {
							_ = req.Reply(true, nil)
						}
						srv := sftp.NewRequestServer(ch, sftpHandlers, sftp.WithStartDirectory("/etc/nginx"))
						_ = srv.Serve()
						_ = ch.Close()
						return
					}
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				case "exec":
					var payload struct{ Command string }
					_ = ssh.Unmarshal(req.Payload, &payload)
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					out := handleSSHExecCommand(payload.Command, prof, sampleCounter)
					_, _ = io.WriteString(ch, out)
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 0}))
					_ = ch.Close()
					return
				case "shell":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					if !shellStarted {
						shellStarted = true
						go serveInteractiveShell(ch, prof, recorder)
					}
				default:
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
				}
			}
		}(chReqs)
	}
}

func handleSSHExecCommand(cmd string, prof mockHostProfile, sampleCounter *atomic.Int64) string {
	switch {
	case strings.Contains(cmd, "===SNS_SEC:SAMPLE_T0==="):
		tick := sampleCounter.Add(1)
		return buildDynamicTelemetry(prof, tick)
	case strings.Contains(cmd, "MEM_KB=") && strings.Contains(cmd, "DISK_KB="):
		if prof.highStress {
			return fmt.Sprintf("HOSTNAME=%s\nOS=%s\nKERNEL=%s\nARCH=x86_64\nCORES=%d\nLOAD=9.85 / 8.40 / 6.95\nUPTIME=7d 2h 36m\nMEM_KB=28835840 32768000\nDISK_KB=477102080 524288000\n",
				prof.hostname, prof.osPretty, prof.kernel, prof.cores)
		}
		return fmt.Sprintf("HOSTNAME=%s\nOS=%s\nKERNEL=%s\nARCH=x86_64\nCORES=%d\nLOAD=1.45 / 1.32 / 1.18\nUPTIME=2d 21h 08m\nMEM_KB=7372800 16384000\nDISK_KB=50331648 104857600\n",
			prof.hostname, prof.osPretty, prof.kernel, prof.cores)
	case strings.Contains(cmd, "authorized_keys"):
		return "DEPLOY_OK\n"
	default:
		return fmt.Sprintf("[%s] Linux %s x86_64 · load average: 1.42, 1.28, 1.15 · Security posture OK\n", prof.hostname, prof.kernel)
	}
}

func serveInteractiveShell(ch ssh.Channel, prof mockHostProfile, recorder *ptyRecorder) {
	defer ch.Close()
	prompt := fmt.Sprintf("\x1b[1;32mroot@%s\x1b[0m:\x1b[1;34m/etc/nginx\x1b[0m# ", prof.hostname)
	banner := fmt.Sprintf(
		"\r\nWelcome to %s (%s x86_64)\r\n * Zero-Knowledge E2EE SSHv2 Channel Verified · Guarded by ServerNeedSafe\r\n * System load: 1.45   Memory usage: 45.0%%   IPv4: 10.16.4.12\r\n\r\n%s",
		prof.osPretty,
		prof.kernel,
		prompt,
	)
	_, _ = io.WriteString(ch, banner)

	var lineBuf strings.Builder
	buf := make([]byte, 1024)
	skipInitialAutoCd := true

	for {
		n, err := ch.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			// Skip the automatic `cd "..." 2>/dev/null && clear\n` injected on session open if present
			if skipInitialAutoCd && strings.Contains(string(chunk), "2>/dev/null && clear") {
				skipInitialAutoCd = false
				continue
			}
			skipInitialAutoCd = false

			if recorder != nil {
				recorder.record(chunk)
			}

			for _, b := range chunk {
				switch b {
				case 0x03: // Ctrl+C
					lineBuf.Reset()
					_, _ = io.WriteString(ch, "^C\r\n"+prompt)
				case 0x04: // Ctrl+D
					_, _ = io.WriteString(ch, "\r\n[EOF shield active]\r\n"+prompt)
				case 0x0c: // Ctrl+L
					current := lineBuf.String()
					_, _ = io.WriteString(ch, "\x1b[2J\x1b[H"+prompt+current)
				case '\r', '\n':
					cmd := strings.TrimSpace(lineBuf.String())
					lineBuf.Reset()
					_, _ = io.WriteString(ch, "\r\n")
					if cmd != "" {
						_, _ = io.WriteString(ch, renderInteractiveCommand(cmd, prof))
					}
					_, _ = io.WriteString(ch, prompt)
				case 0x7f, 0x08: // Backspace
					cur := lineBuf.String()
					if len(cur) > 0 {
						lineBuf.Reset()
						lineBuf.WriteString(cur[:len(cur)-1])
						_, _ = io.WriteString(ch, "\b \b")
					}
				case '\t':
					lineBuf.WriteString("nginx.conf")
					_, _ = io.WriteString(ch, "nginx.conf")
				case 0x1b:
					// Escape sequence prefix
				default:
					if b >= 32 && b < 127 {
						lineBuf.WriteByte(b)
						_, _ = ch.Write([]byte{b})
					}
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func renderInteractiveCommand(cmd string, prof mockHostProfile) string {
	switch {
	case strings.HasPrefix(cmd, "uname"):
		return fmt.Sprintf("Linux %s %s #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux\r\n", prof.hostname, prof.kernel)
	case strings.HasPrefix(cmd, "ss ") || strings.HasPrefix(cmd, "netstat"):
		return "State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port  Process\r\nLISTEN  0       4096    0.0.0.0:22           0.0.0.0:*          users:((\"sshd\",pid=782))\r\nLISTEN  0       4096    0.0.0.0:443          0.0.0.0:*          users:((\"nginx\",pid=1118))\r\n"
	case strings.HasPrefix(cmd, "df"):
		return "Filesystem      Size  Used Avail Use% Mounted on\r\n/dev/nvme0n1p1  100G   48G   52G  48% /\r\n/dev/nvme1n1    200G   84G  116G  42% /srv/gateway\r\n"
	default:
		return fmt.Sprintf("[exec ok] %s\r\n", cmd)
	}
}

func extractTargetServerID(payload map[string]any) string {
	msgs, _ := payload["messages"].([]any)
	for _, m := range msgs {
		mm, _ := m.(map[string]any)
		if mm["role"] == "system" {
			content, _ := mm["content"].(string)
			idx := strings.Index(content, "[server_id=")
			if idx >= 0 {
				rest := content[idx+len("[server_id="):]
				if end := strings.Index(rest, "]"); end > 0 {
					return rest[:end]
				}
			}
		}
	}
	return ""
}

func startMockOpenAIServer(recorder *ptyRecorder) (string, func(), error) {
	mux := http.NewServeMux()
	var chatCalls atomic.Int32

	setCORS := func(w http.ResponseWriter) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, x-api-key, anthropic-version")
	}

	mux.HandleFunc("/__e2e/pty-stats", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodPost && r.URL.Query().Get("reset") == "1" {
			recorder.reset()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(recorder.snapshot())
	})

	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)

		// Check if this is a lightweight TestConnection ping (no tools attached)
		tools, hasTools := payload["tools"].([]any)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher := w.(http.Flusher)

		if !hasTools || len(tools) == 0 {
			_, _ = fmt.Fprintf(w, "data: %s\n\n", `{"choices":[{"delta":{"content":"零知识网关连通正常"}}]}`)
			_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
			flusher.Flush()
			return
		}

		callIdx := chatCalls.Add(1)
		srvID := extractTargetServerID(payload)
		sshdPath := "/etc/ssh/sshd_config"

		// Check last message role & user prompt text
		msgs, _ := payload["messages"].([]any)
		lastRole := ""
		lastUserText := ""
		for _, rawMsg := range msgs {
			if mm, ok := rawMsg.(map[string]any); ok {
				rStr, _ := mm["role"].(string)
				lastRole = rStr
				if rStr == "user" {
					if cStr, ok := mm["content"].(string); ok {
						lastUserText = cStr
					}
				}
			}
		}

		if strings.Contains(lastUserText, "快速诊断命令") || (lastRole == "tool" && callIdx > 1) {
			respChunk := `{"choices":[{"delta":{"content":"已完成主机环境画像归档并生成 **SSH 与网关巡检建议命令**，可直接复制或注入当前终端：\n\n` + "```bash\\nsystemctl reload sshd && sshd -T | grep -E 'permitrootlogin|passwordauthentication'\\n```" + `"}}]}`
			_, _ = fmt.Fprintf(w, "data: %s\n\n", respChunk)
			_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
			flusher.Flush()
			return
		}

		hardenedSSHD := strings.Join([]string{
			"# Managed by ServerNeedSafe Zero-Knowledge SecOps Baseline",
			"Port 22",
			"PermitRootLogin prohibit-password",
			"PasswordAuthentication no",
			"PubkeyAuthentication yes",
			"MaxAuthTries 3",
			"Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
			"",
		}, "\n")

		writeArgsBytes, _ := json.Marshal(map[string]any{
			"server_id": srvID,
			"path":      sshdPath,
			"content":   hardenedSSHD,
			"reason":    "禁用 SSH 密码爆破入口并收敛 Root 登录为仅限 Ed25519 公钥认证",
		})
		memArgsBytes, _ := json.Marshal(map[string]any{
			"server_id":    srvID,
			"summary":      "香港核心边缘接入网关 (Nginx TLS 1.3 + Redis + Docker)",
			"os_arch":      "Ubuntu 24.04.2 LTS x86_64",
			"key_services": []string{"nginx", "sshd", "docker", "fail2ban"},
			"deploy_paths": []string{"/etc/nginx", "/srv/gateway"},
		})

		tcMem, _ := json.Marshal(map[string]any{
			"choices": []any{
				map[string]any{
					"delta": map[string]any{
						"tool_calls": []any{
							map[string]any{
								"index": 0,
								"id":    fmt.Sprintf("call_mem_%d", callIdx),
								"function": map[string]any{
									"name":      "update_host_memory",
									"arguments": string(memArgsBytes),
								},
							},
						},
					},
				},
			},
		})
		tcWrite, _ := json.Marshal(map[string]any{
			"choices": []any{
				map[string]any{
					"delta": map[string]any{
						"tool_calls": []any{
							map[string]any{
								"index": 1,
								"id":    fmt.Sprintf("call_sshd_%d", callIdx),
								"function": map[string]any{
									"name":      "sftp_write_file",
									"arguments": string(writeArgsBytes),
								},
							},
						},
					},
				},
			},
		})

		chunks := []string{
			`{"choices":[{"delta":{"content":"已完成只读探针扫描：发现目标主机 ` + "`/etc/ssh/sshd_config`" + ` 仍开启密码认证（` + "`PasswordAuthentication yes`" + `）且允许 Root 口令登录，存在公网自动化字典爆破风险。\n\n正在为您生成安全加固变更对比（Git Unified Diff）并等待人工审批："}}]}`,
			string(tcMem),
			string(tcWrite),
		}
		for _, c := range chunks {
			_, _ = fmt.Fprintf(w, "data: %s\n\n", c)
			flusher.Flush()
		}
		_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port)
	return baseURL, func() { _ = srv.Close() }, nil
}

func seedInMemSFTP() (sftp.Handlers, error) {
	handlers := sftp.InMemHandler()
	srvConn, cliConn := net.Pipe()
	srv := sftp.NewRequestServer(srvConn, handlers)
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		_ = srv.Serve()
	}()

	cli, err := sftp.NewClientPipe(cliConn, cliConn)
	if err != nil {
		_ = srvConn.Close()
		_ = cliConn.Close()
		return handlers, err
	}

	dirs := []string{
		"/etc",
		"/etc/ssh",
		"/etc/nginx",
		"/etc/nginx/conf.d",
		"/etc/nginx/logs",
		"/root",
	}
	for _, d := range dirs {
		if err := cli.MkdirAll(d); err != nil {
			_ = cli.Close()
			return handlers, err
		}
	}

	files := map[string]string{
		"/etc/ssh/sshd_config": strings.Join([]string{
			"# OpenSSH Daemon Configuration",
			"Port 22",
			"PermitRootLogin yes",
			"PasswordAuthentication yes",
			"PubkeyAuthentication yes",
			"MaxAuthTries 6",
			"",
		}, "\n"),
		"/etc/nginx/nginx.conf": strings.Join([]string{
			"user www-data;",
			"worker_processes auto;",
			"events { worker_connections 8192; }",
			"http {",
			"    ssl_protocols TLSv1.3;",
			"    include /etc/nginx/conf.d/*.conf;",
			"}",
			"",
		}, "\n"),
		"/etc/nginx/prod-gateway-tls-upstream-security-hardening.conf": strings.Join([]string{
			"# Production BGP Edge TLS 1.3 Upstream Hardening",
			"add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;",
			"ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;",
			"",
		}, "\n"),
		"/etc/nginx/deploy-release.sh": "#!/usr/bin/env bash\nset -euo pipefail\ndocker compose pull && docker compose up -d --remove-orphans\n",
		"/etc/nginx/.env.production":   "NODE_ENV=production\nGATEWAY_REGION=ap-east-1\nTLS_MIN_VERSION=1.3\n",
		"/etc/nginx/logs/access.log":   "2026-11-18T08:15:02Z 200 GET /api/health 1.2ms\n",
	}
	for fullPath, content := range files {
		f, err := cli.Create(fullPath)
		if err != nil {
			_ = cli.Close()
			return handlers, err
		}
		if _, err := f.Write([]byte(content)); err != nil {
			_ = f.Close()
			_ = cli.Close()
			return handlers, err
		}
		_ = f.Close()
		_ = cli.Chmod(fullPath, 0o644)
	}
	_ = cli.Chmod("/etc/nginx/deploy-release.sh", 0o755)
	_ = cli.Close()
	_ = cliConn.Close()
	_ = srvConn.Close()
	<-srvDone
	return handlers, nil
}

func main() {
	distDir := flag.String("dist", "", "Path to built web/dist directory")
	flag.Parse()

	resolvedDist := *distDir
	if resolvedDist == "" {
		candidates := []string{
			"dist",
			"web/dist",
			filepath.Join("..", "dist"),
		}
		for _, c := range candidates {
			if st, err := os.Stat(filepath.Join(c, "index.html")); err == nil && !st.IsDir() {
				resolvedDist = c
				break
			}
		}
	}
	if resolvedDist == "" {
		fmt.Fprintln(os.Stderr, "cannot locate built web/dist directory")
		os.Exit(1)
	}

	tmpDir, err := os.MkdirTemp("", "sns-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkdirtemp failed: %v\n", err)
		os.Exit(1)
	}
	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}
	defer cleanup()

	memSFTP, err := seedInMemSFTP()
	if err != nil {
		fmt.Fprintf(os.Stderr, "seed in-mem sftp failed: %v\n", err)
		os.Exit(1)
	}

	recorder := &ptyRecorder{}
	var sampleCounterEdge atomic.Int64
	var sampleCounterDB atomic.Int64

	sshUser := "root"
	sshPass := "DemoSSHPass!2026"

	edgePort, stopEdgeSSH, err := startEmbeddedSSHNode(
		sshUser,
		sshPass,
		mockHostProfile{
			hostname:   "hk-edge-gw-01",
			osPretty:   "Ubuntu 24.04.2 LTS",
			kernel:     "6.8.0-48-generic",
			cores:      8,
			cpuModel:   "AMD EPYC 9654 96-Core Processor",
			highStress: false,
		},
		memSFTP,
		recorder,
		&sampleCounterEdge,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start edge ssh failed: %v\n", err)
		os.Exit(1)
	}
	defer stopEdgeSSH()

	dbPort, stopDBSSH, err := startEmbeddedSSHNode(
		sshUser,
		sshPass,
		mockHostProfile{
			hostname:   "sg-prod-pg-02",
			osPretty:   "Debian GNU/Linux 12 (bookworm)",
			kernel:     "6.1.0-27-amd64",
			cores:      16,
			cpuModel:   "Intel(R) Xeon(R) Platinum 8488C",
			highStress: true,
		},
		memSFTP,
		nil,
		&sampleCounterDB,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start db ssh failed: %v\n", err)
		os.Exit(1)
	}
	defer stopDBSSH()

	mockLLMBase, stopLLM, err := startMockOpenAIServer(recorder)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start mock llm failed: %v\n", err)
		os.Exit(1)
	}
	defer stopLLM()

	store, err := vault.NewStore(tmpDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "store init failed: %v\n", err)
		os.Exit(1)
	}
	authMgr, err := auth.NewManager(auth.DefaultSessionTTL, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "auth mgr failed: %v\n", err)
		os.Exit(1)
	}

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "http listen failed: %v\n", err)
		os.Exit(1)
	}
	listenAddr := httpLn.Addr().String()

	apiServer := api.NewServer(api.Config{
		DeployMode:             "server",
		Store:                  store,
		Auth:                   authMgr,
		StaticFS:               os.DirFS(resolvedDist),
		DisableAutoUpdateCheck: true,
		DisableAutoVulnSync:    true,
	})
	// Seed deterministic vulnerability advisories once vault is initialized in E2E tests
	store.RegisterOnReady(func() {
		now := time.Now().UTC()
		seedAdvisories := []vault.VulnAdvisory{
			{
				ID:            "CVE-2026-90001",
				CVEID:         "CVE-2026-90001",
				AppIDs:        []string{"openssl"},
				AppNames:      []string{"OpenSSL"},
				Categories:    []string{"os_security"},
				Title:         "OpenSSL TLS 1.3 Handshake Critical Memory Corruption",
				Summary:       "Remote unauthenticated memory corruption during TLS 1.3 handshake fixed in OpenSSL 3.0.16.",
				Severity:      vault.VulnSeverityCritical,
				CVSSScore:     9.8,
				AffectedText:  "< 3.0.16",
				FixedVersion:  "3.0.16",
				FixedVersions: []string{"3.0.16"},
				HasFix:        true,
				IsKEV:         true,
				KEVDateAdded:  now.Format("2006-01-02"),
				KEVDueDate:    now.AddDate(0, 0, 14).Format("2006-01-02"),
				KEVAction:     "Apply OpenSSL 3.0.16 security update immediately.",
				Sources:       []string{"OpenSSL 官方公告", "CISA KEV"},
				PrimarySource: "OpenSSL 官方公告",
				OfficialURL:   "https://openssl-library.org/news/vulnerabilities/",
				PublishedAt:   now.Add(-2 * time.Hour),
				ModifiedAt:    now.Add(-1 * time.Hour),
				FirstSeenAt:   now.Add(-30 * time.Minute),
			},
			{
				ID:            "CVE-2026-90002",
				CVEID:         "CVE-2026-90002",
				AppIDs:        []string{"openssh"},
				AppNames:      []string{"OpenSSH"},
				Categories:    []string{"os_security"},
				Title:         "OpenSSH Pre-Auth Signal Handler Race Condition",
				Summary:       "High-severity race condition in sshd pre-auth handling resolved in OpenSSH 9.9p2.",
				Severity:      vault.VulnSeverityHigh,
				CVSSScore:     8.1,
				AffectedText:  "< 9.9p2",
				FixedVersion:  "9.9p2",
				FixedVersions: []string{"9.9p2"},
				HasFix:        true,
				Sources:       []string{"OSV.dev", "GitHub Advisory"},
				PrimarySource: "GitHub Advisory",
				OfficialURL:   "https://www.openssh.com/security.html",
				PublishedAt:   now.Add(-6 * time.Hour),
				ModifiedAt:    now.Add(-5 * time.Hour),
				FirstSeenAt:   now.Add(-30 * time.Minute),
			},
			{
				ID:            "CVE-2026-90003",
				CVEID:         "CVE-2026-90003",
				AppIDs:        []string{"nginx"},
				AppNames:      []string{"Nginx"},
				Categories:    []string{"web_proxy"},
				Title:         "Nginx HTTP/3 QUIC Stream Reset Null Pointer Dereference",
				Summary:       "Worker process crash via crafted HTTP/3 frames patched in Nginx 1.27.4+.",
				Severity:      vault.VulnSeverityMedium,
				CVSSScore:     5.9,
				AffectedText:  "1.25.0-1.27.3",
				FixedVersion:  "1.27.4",
				FixedVersions: []string{"1.27.4"},
				HasFix:        true,
				Sources:       []string{"Nginx 官方公告"},
				PrimarySource: "Nginx 官方公告",
				OfficialURL:   "https://nginx.org/en/security_advisories.html",
				PublishedAt:   now.Add(-24 * time.Hour),
				ModifiedAt:    now.Add(-20 * time.Hour),
				FirstSeenAt:   now.Add(-30 * time.Minute),
			},
		}
		store.SaveVulnSyncResults(seedAdvisories, []vault.VulnSourceStatus{
			{ID: "vendor-openssl", Name: "OpenSSL 官方安全公告", Kind: "vendor", OK: true, ItemCount: 1, DurationMs: 42, LastSyncAt: &now},
			{ID: "osv-dev", Name: "OSV.dev 官方生态漏洞库", Kind: "osv", OK: true, ItemCount: 1, DurationMs: 55, LastSyncAt: &now},
			{ID: "vendor-nginx", Name: "Nginx 官方安全公告", Kind: "vendor", OK: true, ItemCount: 1, DurationMs: 38, LastSyncAt: &now},
		}, "", 90, 3000)
	})

	httpServer := &http.Server{
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		_ = httpServer.Serve(httpLn)
	}()

	readyPayload := map[string]any{
		"base_url":      "http://" + listenAddr,
		"ssh_host":      "127.0.0.1",
		"ssh_edge_port": edgePort,
		"ssh_db_port":   dbPort,
		"ssh_user":      sshUser,
		"ssh_pass":      sshPass,
		"sftp_root":     "/etc/nginx",
		"llm_base_url":  mockLLMBase + "/v1",
		"control_url":   mockLLMBase + "/__e2e/pty-stats",
		"temp_dir":      tmpDir,
	}
	encoded, _ := json.Marshal(readyPayload)
	fmt.Println(string(encoded))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	stdinClosed := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(stdinClosed)
	}()

	select {
	case <-sigCh:
	case <-stdinClosed:
	}

	authMgr.RevokeAll()
	apiServer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}
