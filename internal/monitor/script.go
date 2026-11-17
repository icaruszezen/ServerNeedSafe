package monitor

import (
	"strings"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
)

var defaultProbeServices = []string{
	"sshd", "ssh", "docker", "nginx", "caddy", "postgresql",
	"mysql", "mariadb", "redis", "redis-server", "ufw", "firewalld", "fail2ban", "cron", "crond",
}

func sanitizeShellWord(s string) string {
	var b strings.Builder
	for _, ch := range strings.TrimSpace(s) {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '@' {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

// buildDeepTelemetryScript constructs a single-pass, POSIX-compatible, locale-neutral shell script
// that collects all-around server metrics with dual-point rate sampling in ~300ms.
func buildDeepTelemetryScript(settings vault.MonitorSettings, watchedServices []string) string {
	var b strings.Builder
	b.WriteString("export LC_ALL=C LANG=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n")

	// T0 Counter Sample (Uptime + CPU + Context Switches + Net Dev + Diskstats)
	b.WriteString(`echo "===SNS_SEC:SAMPLE_T0==="
[ -r /proc/uptime ] && awk '{printf "UP=%s\n", $1}' /proc/uptime
[ -r /proc/stat ] && awk '/^cpu / {print "CPU=" $0} /^ctxt / {print "CTXT=" $2}' /proc/stat
[ -r /proc/net/dev ] && awk 'NR>2 {gsub(/:/, " "); printf "NET=%s %s %s %s %s %s %s %s %s\n", $1, $2, $3, $4, $5, $10, $11, $12, $13}' /proc/net/dev
[ -r /proc/diskstats ] && awk '$3 ~ /^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+|dm-[0-9]+)$/ {printf "BIO=%s %s %s %s %s\n", $3, $4, $6, $8, $10}' /proc/diskstats
`)

	// System Identity, Load, Clock, Thermal
	b.WriteString(`echo "===SNS_SEC:SYS==="
printf "HOSTNAME=%s\n" "$(hostname 2>/dev/null || uname -n 2>/dev/null)"
OS_NAME=""
if [ -r /etc/os-release ]; then
  OS_NAME=$(. /etc/os-release 2>/dev/null && printf "%s" "${PRETTY_NAME:-$NAME}")
fi
[ -z "$OS_NAME" ] && OS_NAME=$(uname -s 2>/dev/null)
printf "OS=%s\n" "$OS_NAME"
printf "KERNEL=%s\n" "$(uname -r 2>/dev/null)"
printf "ARCH=%s\n" "$(uname -m 2>/dev/null)"
printf "CORES=%s\n" "$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1)"
if [ -r /proc/cpuinfo ]; then
  CPU_M=$(awk -F: '/model name|Processor|cpu model/ {gsub(/^[ \t]+/, "", $2); print $2; exit}' /proc/cpuinfo 2>/dev/null)
  [ -n "$CPU_M" ] && printf "CPU_MODEL=%s\n" "$CPU_M"
fi
VIRT_T=$(systemd-detect-virt 2>/dev/null || true)
[ -n "$VIRT_T" ] && printf "VIRT=%s\n" "$VIRT_T"
[ -r /proc/uptime ] && awk '{printf "UPTIME_SEC=%s\n", $1}' /proc/uptime
[ -r /proc/loadavg ] && awk '{printf "LOAD=%s %s %s %s\n", $1, $2, $3, $4}' /proc/loadavg
printf "SERVER_TIME=%s\n" "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
printf "TIMEZONE=%s\n" "$(date '+%Z' 2>/dev/null)"
NTP_SYNC=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo "")
[ -n "$NTP_SYNC" ] && printf "NTP=%s\n" "$NTP_SYNC"
if ls /sys/class/thermal/thermal_zone*/temp >/dev/null 2>&1; then
  MAX_T=$(cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null | awk '$1+0 > m {m=$1+0} END {if(m>0) printf "%.1f", (m>1000 ? m/1000.0 : m)}')
  [ -n "$MAX_T" ] && printf "TEMP_C=%s\n" "$MAX_T"
fi
`)

	// Memory, Swap, File Descriptors, OOM Kills
	b.WriteString(`echo "===SNS_SEC:MEM==="
[ -r /proc/meminfo ] && awk '/^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SReclaimable|SwapTotal|SwapFree):/ {gsub(/:/, "", $1); printf "%s=%s\n", $1, $2}' /proc/meminfo
[ -r /proc/sys/fs/file-nr ] && awk '{printf "FILE_NR=%s %s\n", $1, $3}' /proc/sys/fs/file-nr
[ -r /proc/vmstat ] && awk '/^oom_kill / {printf "OOM_KILL=%s\n", $2}' /proc/vmstat
`)

	// Disk Mounts & Inodes (handle unnamed container/tmpfs mounts where column 1 is empty -> NF==6 / NF==5)
	b.WriteString(`echo "===SNS_SEC:DISK==="
df -PTk 2>/dev/null | awk 'NR>1 {
  if (NF==6) { dev="none"; fst=$1; tot=$2; used=$3; av=$4; cap=$5; mnt=$6 }
  else if (NF>=7) { dev=$1; fst=$2; tot=$3; used=$4; av=$5; cap=$6; mnt=$7 }
  else next;
  if (fst !~ /^(tmpfs|devtmpfs|squashfs|overlay|proc|sysfs|cgroup|cgroup2|nsfs|tracefs|efivarfs|autofs|mqueue|hugetlbfs|debugfs|pstore|securityfs|configfs|fusectl|fuse\.portal|ramfs)$/)
    printf "FS=%s|%s|%s|%s|%s|%s|%s\n", dev, fst, tot, used, av, cap, mnt
}'
echo "===SNS_SEC:INODE==="
df -Pi 2>/dev/null | awk 'NR>1 {
  if (NF==5) printf "INODE=%s|%s\n", $5, $4;
  else if (NF>=6) printf "INODE=%s|%s\n", $6, $5;
}'
`)

	// Interface IPv4 & Link States + Kernel TCP/UDP Socket State Matrix
	b.WriteString(`echo "===SNS_SEC:IFACE==="
ip -4 -o addr show 2>/dev/null | awk '{split($4,a,"/"); printf "IP4=%s|%s\n", $2, a[1]}'
for devp in /sys/class/net/*; do
  [ -e "$devp/operstate" ] || continue
  dn=$(basename "$devp")
  st=$(cat "$devp/operstate" 2>/dev/null)
  printf "OPER=%s|%s\n" "$dn" "$st"
done
echo "===SNS_SEC:SOCK==="
awk 'FNR>1 {st[$4]++} END {for (k in st) printf "TCP_%s=%d\n", k, st[k]}' /proc/net/tcp /proc/net/tcp6 2>/dev/null
UDP_CNT=$(awk 'FNR>1 {c++} END {print c+0}' /proc/net/udp /proc/net/udp6 2>/dev/null)
printf "UDP_ALL=%s\n" "${UDP_CNT:-0}"
`)

	// Process States & Top CPU / Memory Processes
	if settings.CollectProcesses {
		b.WriteString(`echo "===SNS_SEC:PROC==="
ps -eo stat= 2>/dev/null | awk '{
  tot++;
  c=substr($1,1,1);
  if (c=="R") run++;
  else if (c=="Z") zom++;
  else if (c=="D") blk++;
  else slp++;
} END {printf "PSTAT=%d %d %d %d %d\n", tot+0, run+0, slp+0, zom+0, blk+0}'
(ps -eo pid=,user=,pcpu=,pmem=,rss=,stat=,etime=,comm= --sort=-pcpu 2>/dev/null || ps -eo pid=,user=,pcpu=,pmem=,rss=,stat=,etime=,comm= 2>/dev/null) | head -n 8 | awk '{printf "TOP_CPU=%s|%s|%s|%s|%s|%s|%s|%s\n", $1, $2, $3, $4, $5, $6, $7, $8}'
(ps -eo pid=,user=,pcpu=,pmem=,rss=,stat=,etime=,comm= --sort=-rss 2>/dev/null || ps -eo pid=,user=,pcpu=,pmem=,rss=,stat=,etime=,comm= 2>/dev/null) | head -n 8 | awk '{printf "TOP_MEM=%s|%s|%s|%s|%s|%s|%s|%s\n", $1, $2, $3, $4, $5, $6, $7, $8}'
`)
	}

	// Listening Ports, Systemd Services, and Docker Containers
	if settings.CollectPortsAndServices {
		b.WriteString(`echo "===SNS_SEC:PORTS==="
if command -v ss >/dev/null 2>&1; then
  ss -tulnpH 2>/dev/null | head -n 80
elif command -v netstat >/dev/null 2>&1; then
  netstat -tulnp 2>/dev/null | awk 'NR>2' | head -n 80
fi
`)

		var watchedClean []string
		watchedSet := make(map[string]bool)
		for _, ws := range watchedServices {
			w := sanitizeShellWord(ws)
			if w != "" && !watchedSet[w] {
				watchedSet[w] = true
				watchedClean = append(watchedClean, w)
			}
		}

		var autoClean []string
		for _, ds := range defaultProbeServices {
			if !watchedSet[ds] {
				autoClean = append(autoClean, ds)
			}
		}

		b.WriteString("echo \"===SNS_SEC:SYSTEMD===\"\n")
		b.WriteString("if command -v systemctl >/dev/null 2>&1; then\n")
		b.WriteString("  systemctl --failed --no-legend --no-pager --plain 2>/dev/null | head -n 15 | awk '{printf \"FAILED_UNIT=%s\\n\", $1}'\n")
		if len(watchedClean) > 0 {
			b.WriteString("  for u in " + strings.Join(watchedClean, " ") + "; do\n")
			b.WriteString("    st=$(systemctl is-active \"$u\" 2>/dev/null || true)\n")
			b.WriteString("    [ -z \"$st\" ] && st=\"not-found\"\n")
			b.WriteString("    printf \"SVC=%s|%s|watched\\n\" \"$u\" \"$st\"\n")
			b.WriteString("  done\n")
		}
		if len(autoClean) > 0 {
			b.WriteString("  for u in " + strings.Join(autoClean, " ") + "; do\n")
			b.WriteString("    ld=$(systemctl show \"$u\" -p LoadState --value 2>/dev/null || true)\n")
			b.WriteString("    if [ \"$ld\" = \"loaded\" ]; then\n")
			b.WriteString("      st=$(systemctl is-active \"$u\" 2>/dev/null || echo inactive)\n")
			b.WriteString("      printf \"SVC=%s|%s|auto\\n\" \"$u\" \"$st\"\n")
			b.WriteString("    fi\n")
			b.WriteString("  done\n")
		}
		b.WriteString("fi\n")

		b.WriteString(`echo "===SNS_SEC:DOCKER==="
if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then
    echo "DOCKER_OK=1"
    docker ps -a --no-trunc --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}|{{.Status}}' 2>/dev/null | head -n 30 | awk '{printf "CTR=%s\n", $0}'
  fi
fi
`)
	}

	// Security Posture: Logged-in Sessions, SSH Brute-Force Audit, Firewall, MAC, Reboot Flag
	if settings.CollectSecurity {
		b.WriteString(`echo "===SNS_SEC:SEC==="
who 2>/dev/null | head -n 12 | awk '{printf "WHO=%s|%s|%s %s|%s\n", $1, $2, $3, $4, $5}'
[ -r /etc/passwd ] && awk -F: '($3 == 0) {printf "UID0=%s\n", $1}' /etc/passwd 2>/dev/null
if [ -f /var/run/reboot-required ]; then echo "REBOOT_REQ=1"; else echo "REBOOT_REQ=0"; fi
FW_ST="unknown"; FW_DET=""
if command -v ufw >/dev/null 2>&1; then
  UFW_OUT=$(ufw status 2>/dev/null || true)
  if echo "$UFW_OUT" | grep -qi "Status: active"; then FW_ST="active"; FW_DET="ufw";
  elif echo "$UFW_OUT" | grep -qi "Status: inactive"; then FW_ST="inactive"; FW_DET="ufw"; fi
fi
if [ "$FW_ST" = "unknown" ] && command -v firewall-cmd >/dev/null 2>&1; then
  if firewall-cmd --state 2>/dev/null | grep -qi "running"; then FW_ST="active"; FW_DET="firewalld"; fi
fi
if [ "$FW_ST" = "unknown" ] && command -v systemctl >/dev/null 2>&1; then
  for fwsvc in ufw firewalld nftables netfilter-persistent iptables; do
    if [ "$(systemctl is-active "$fwsvc" 2>/dev/null || true)" = "active" ]; then
      FW_ST="active"; FW_DET="$fwsvc"; break
    fi
  done
fi
printf "FW=%s|%s\n" "$FW_ST" "$FW_DET"
if command -v getenforce >/dev/null 2>&1; then
  printf "MAC=SELinux:%s\n" "$(getenforce 2>/dev/null)"
elif [ -r /sys/module/apparmor/parameters/enabled ]; then
  printf "MAC=AppArmor:%s\n" "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)"
fi
SSH_LOG=""
if [ -r /var/log/auth.log ]; then
  SSH_LOG=$(tail -n 600 /var/log/auth.log 2>/dev/null | grep -E "sshd.*(Failed password|Invalid user)" || true)
elif [ -r /var/log/secure ]; then
  SSH_LOG=$(tail -n 600 /var/log/secure 2>/dev/null | grep -E "sshd.*(Failed password|Invalid user)" || true)
elif command -v journalctl >/dev/null 2>&1; then
  SSH_LOG=$(journalctl -u ssh -u sshd --since "2 hours ago" --no-pager 2>/dev/null | grep -E "Failed password|Invalid user" || true)
fi
if [ -n "$SSH_LOG" ]; then
  FAIL_CNT=$(printf "%s\n" "$SSH_LOG" | grep -c . || echo 0)
  printf "SSH_FAIL_CNT=%s\n" "$FAIL_CNT"
  printf "%s\n" "$SSH_LOG" | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{c[$2]++} END {for (ip in c) printf "%d %s\n", c[ip], ip}' | sort -rn | head -n 5 | awk '{printf "SSH_FAIL_IP=%s(%s)\n", $2, $1}'
else
  echo "SSH_FAIL_CNT=0"
fi
`)
	}

	// Ensure >= 250ms delta before T1 sample so real-time CPU%, Net B/s, and Disk I/O B/s are accurate
	b.WriteString(`sleep 0.25 2>/dev/null || sleep 1
echo "===SNS_SEC:SAMPLE_T1==="
[ -r /proc/uptime ] && awk '{printf "UP=%s\n", $1}' /proc/uptime
[ -r /proc/stat ] && awk '/^cpu / {print "CPU=" $0} /^ctxt / {print "CTXT=" $2}' /proc/stat
[ -r /proc/net/dev ] && awk 'NR>2 {gsub(/:/, " "); printf "NET=%s %s %s %s %s %s %s %s %s\n", $1, $2, $3, $4, $5, $10, $11, $12, $13}' /proc/net/dev
[ -r /proc/diskstats ] && awk '$3 ~ /^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+|dm-[0-9]+)$/ {printf "BIO=%s %s %s %s %s\n", $3, $4, $6, $8, $10}' /proc/diskstats
true
`)
	return b.String()
}
