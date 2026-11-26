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
// that collects all-around server metrics with dual-point rate sampling.
// It preserves existing Linux (/proc, /sys, GNU) paths unchanged while automatically adapting to macOS (Darwin).
func buildDeepTelemetryScript(settings vault.MonitorSettings, watchedServices []string) string {
	var b strings.Builder
	b.WriteString(`export LC_ALL=C LANG=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SNS_OS=$(uname -s 2>/dev/null || echo Linux)
if [ "$SNS_OS" = "Darwin" ]; then
  PATH="$PATH:/opt/homebrew/sbin:/opt/homebrew/bin:$HOME/.orbstack/bin:/Applications/Docker.app/Contents/Resources/bin"
  export PATH
fi
`)

	const darwinCounterSampleBlock = `  NOW_TS=$(perl -MTime::HiRes=time -e 'printf "%.3f\n", time' 2>/dev/null || date +%s 2>/dev/null || echo 0)
  printf "UP=%s\n" "$NOW_TS"
  netstat -ibn 2>/dev/null | awk '$3 ~ /^<Link#/ && NF >= 10 {
    dev = $1; gsub(/\*$/, "", dev);
    if (dev ~ /^(lo0|gif[0-9]*|stf[0-9]*|anpi[0-9]*|awdl[0-9]*|llw[0-9]*|ap[0-9]*|XHC[0-9]*|pktap[0-9]*|iptap[0-9]*)$/) next;
    if (seen[dev]++) next;
    ipkts = $(NF-6)+0; ierrs = $(NF-5)+0; ibytes = $(NF-4)+0;
    opkts = $(NF-3)+0; oerrs = $(NF-2)+0; obytes = $(NF-1)+0;
    if (dev !~ /^en[0-9]+$/ && ibytes == 0 && obytes == 0) next;
    printf "NET=%s %.0f %.0f %.0f 0 %.0f %.0f %.0f 0\n", dev, ibytes, ipkts, ierrs, obytes, opkts, oerrs;
  }'
  ioreg -c IOBlockStorageDriver -r -k Statistics -w 0 2>/dev/null | awk '/"Statistics" = \{/ {
    idx++;
    br=0; bw=0; or_=0; ow=0; s=$0;
    if (match(s, /"Bytes \(Read\)"=[0-9]+/)) { t=substr(s, RSTART, RLENGTH); sub(/.*=/, "", t); br=t+0 }
    if (match(s, /"Bytes \(Write\)"=[0-9]+/)) { t=substr(s, RSTART, RLENGTH); sub(/.*=/, "", t); bw=t+0 }
    if (match(s, /"Operations \(Read\)"=[0-9]+/)) { t=substr(s, RSTART, RLENGTH); sub(/.*=/, "", t); or_=t+0 }
    if (match(s, /"Operations \(Write\)"=[0-9]+/)) { t=substr(s, RSTART, RLENGTH); sub(/.*=/, "", t); ow=t+0 }
    if (br>0 || bw>0 || or_>0 || ow>0) {
      printf "BIO=disk%d %.0f %.0f %.0f %.0f\n", idx-1, or_, int(br/512), ow, int(bw/512);
    }
  }'
`

	// T0 Counter Sample (Uptime + CPU + Context Switches + Net Dev + Diskstats)
	b.WriteString("echo \"===SNS_SEC:SAMPLE_T0===\"\n")
	b.WriteString("if [ \"$SNS_OS\" = \"Darwin\" ]; then\n")
	b.WriteString(darwinCounterSampleBlock)
	b.WriteString(`else
  [ -r /proc/uptime ] && awk '{printf "UP=%s\n", $1}' /proc/uptime
  [ -r /proc/stat ] && awk '/^cpu / {print "CPU=" $0} /^ctxt / {print "CTXT=" $2}' /proc/stat
  [ -r /proc/net/dev ] && awk 'NR>2 {gsub(/:/, " "); printf "NET=%s %s %s %s %s %s %s %s %s\n", $1, $2, $3, $4, $5, $10, $11, $12, $13}' /proc/net/dev
  [ -r /proc/diskstats ] && awk '$3 ~ /^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+|dm-[0-9]+)$/ {printf "BIO=%s %s %s %s %s\n", $3, $4, $6, $8, $10}' /proc/diskstats
fi
`)

	// System Identity, Load, Clock, Thermal
	b.WriteString(`echo "===SNS_SEC:SYS==="
printf "HOSTNAME=%s\n" "$(hostname 2>/dev/null || uname -n 2>/dev/null)"
if [ "$SNS_OS" = "Darwin" ]; then
  OS_P=$(sw_vers -productName 2>/dev/null || echo "macOS")
  OS_V=$(sw_vers -productVersion 2>/dev/null || true)
  OS_B=$(sw_vers -buildVersion 2>/dev/null || true)
  if [ -n "$OS_V" ] && [ -n "$OS_B" ]; then
    printf "OS=%s %s (%s)\n" "$OS_P" "$OS_V" "$OS_B"
  elif [ -n "$OS_V" ]; then
    printf "OS=%s %s\n" "$OS_P" "$OS_V"
  else
    printf "OS=%s\n" "$(uname -s 2>/dev/null)"
  fi
  printf "KERNEL=%s\n" "$(uname -r 2>/dev/null)"
  printf "ARCH=%s\n" "$(uname -m 2>/dev/null)"
  printf "CORES=%s\n" "$(sysctl -n hw.ncpu 2>/dev/null || echo 1)"
  CPU_M=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)
  [ -z "$CPU_M" ] && CPU_M=$(sysctl -n hw.model 2>/dev/null || true)
  [ -n "$CPU_M" ] && printf "CPU_MODEL=%s\n" "$CPU_M"
  HV_VMM=$(sysctl -n kern.hv_vmm_present 2>/dev/null || echo 0)
  [ "$HV_VMM" = "1" ] && printf "VIRT=apple-vm\n"
  BOOT_SEC=$(sysctl -n kern.boottime 2>/dev/null | awk '{for(i=1;i<=NF;i++) if(($i=="sec" || $i=="{sec") && $(i+1)=="="){v=$(i+2); gsub(/[^0-9]/,"",v); if(v ~ /^[0-9]+$/){print v; exit}}}')
  NOW_SEC=$(date +%s 2>/dev/null || echo 0)
  if [ -n "$BOOT_SEC" ] && [ "$BOOT_SEC" -gt 0 ] 2>/dev/null && [ "$NOW_SEC" -ge "$BOOT_SEC" ] 2>/dev/null; then
    printf "UPTIME_SEC=%s\n" "$((NOW_SEC - BOOT_SEC))"
  fi
  sysctl -n vm.loadavg 2>/dev/null | awk '{gsub(/[{}]/, ""); if(NF>=3) printf "LOAD=%s %s %s\n", $1, $2, $3}'
  printf "SERVER_TIME=%s\n" "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
  printf "TIMEZONE=%s\n" "$(date '+%Z' 2>/dev/null)"
  if pgrep -x timed >/dev/null 2>&1; then printf "NTP=yes\n"; fi
else
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
fi
`)

	// Memory, Swap, File Descriptors, OOM Kills
	b.WriteString(`echo "===SNS_SEC:MEM==="
if [ "$SNS_OS" = "Darwin" ]; then
  MEM_TOTAL_B=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
  PAGE_SZ=$(sysctl -n hw.pagesize 2>/dev/null || pagesize 2>/dev/null || echo 4096)
  vm_stat 2>/dev/null | awk -v total_b="$MEM_TOTAL_B" -v pgsz="$PAGE_SZ" '
    BEGIN { if (pgsz+0 <= 0) pgsz = 4096; }
    /page size of [0-9]+ bytes/ {
      s=$0; sub(/.*page size of /, "", s); sub(/ bytes.*/, "", s);
      if (s+0 > 0) pgsz = s+0;
    }
    /^Pages free:/ { gsub(/[^0-9]/, "", $NF); p_free = $NF+0 }
    /^Pages active:/ { gsub(/[^0-9]/, "", $NF); p_active = $NF+0 }
    /^Pages inactive:/ { gsub(/[^0-9]/, "", $NF); p_inactive = $NF+0 }
    /^Pages speculative:/ { gsub(/[^0-9]/, "", $NF); p_spec = $NF+0 }
    /^Pages wired down:/ { gsub(/[^0-9]/, "", $NF); p_wired = $NF+0 }
    /^Pages purgeable:/ { gsub(/[^0-9]/, "", $NF); p_purge = $NF+0 }
    /^File-backed pages:/ { gsub(/[^0-9]/, "", $NF); p_file = $NF+0; has_file = 1 }
    /^Anonymous pages:/ { gsub(/[^0-9]/, "", $NF); p_anon = $NF+0; has_anon = 1 }
    /^Pages occupied by compressor:/ { gsub(/[^0-9]/, "", $NF); p_comp = $NF+0 }
    END {
      total_kb = int((total_b+0) / 1024);
      if (total_kb <= 0) exit;
      if (has_anon) {
        app_p = p_anon - p_purge;
        if (app_p < 0) app_p = 0;
        used_p = app_p + p_wired + p_comp;
      } else {
        used_p = p_active + p_wired + p_comp;
      }
      used_kb = int(used_p * pgsz / 1024);
      if (used_kb > total_kb) used_kb = total_kb;
      avail_kb = total_kb - used_kb;
      free_kb = int((p_free + p_spec) * pgsz / 1024);
      cached_kb = has_file ? int((p_file + p_purge) * pgsz / 1024) : int((p_inactive + p_purge) * pgsz / 1024);
      printf "MemTotal=%.0f\nMemFree=%.0f\nMemAvailable=%.0f\nBuffers=0\nCached=%.0f\nSReclaimable=0\n", total_kb, free_kb, avail_kb, cached_kb;
    }'
  sysctl -n vm.swapusage 2>/dev/null | awk '
    function to_kb(s,   u, n) {
      u = substr(s, length(s), 1);
      n = s; gsub(/[^0-9.]/, "", n); n = n + 0;
      if (u == "T" || u == "t") return int(n * 1073741824);
      if (u == "G" || u == "g") return int(n * 1048576);
      if (u == "M" || u == "m") return int(n * 1024);
      if (u == "K" || u == "k") return int(n);
      return int(n / 1024);
    }
    {
      for (i=1; i<=NF; i++) {
        if ($i == "total" && $(i+1) == "=") tot = to_kb($(i+2));
        if ($i == "free" && $(i+1) == "=") fre = to_kb($(i+2));
      }
    }
    END {
      if (tot > 0) printf "SwapTotal=%.0f\nSwapFree=%.0f\n", tot, fre;
    }'
  FD_USED=$(sysctl -n kern.num_files 2>/dev/null || true)
  FD_MAX=$(sysctl -n kern.maxfiles 2>/dev/null || true)
  if [ -n "$FD_USED" ] && [ -n "$FD_MAX" ] && [ "$FD_MAX" -gt 0 ] 2>/dev/null; then
    printf "FILE_NR=%s %s\n" "$FD_USED" "$FD_MAX"
  fi
else
  [ -r /proc/meminfo ] && awk '/^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SReclaimable|SwapTotal|SwapFree):/ {gsub(/:/, "", $1); printf "%s=%s\n", $1, $2}' /proc/meminfo
  [ -r /proc/sys/fs/file-nr ] && awk '{printf "FILE_NR=%s %s\n", $1, $3}' /proc/sys/fs/file-nr
  [ -r /proc/vmstat ] && awk '/^oom_kill / {printf "OOM_KILL=%s\n", $2}' /proc/vmstat
fi
`)

	// Disk Mounts & Inodes
	b.WriteString(`echo "===SNS_SEC:DISK==="
if [ "$SNS_OS" = "Darwin" ]; then
  (
    mount 2>/dev/null | awk '{
      p1 = index($0, " on ");
      p2 = 0;
      for (i = length($0) - 1; i > p1; i--) {
        if (substr($0, i, 2) == " (") { p2 = i; break }
      }
      if (p1 > 0 && p2 > p1) {
        mnt = substr($0, p1 + 4, p2 - p1 - 4);
        rest = substr($0, p2 + 2);
        split(rest, a, "[,)]");
        fst = a[1];
        gsub(/^[ \t]+|[ \t]+$/, "", fst);
        printf "MNT|%s|%s\n", mnt, fst;
      }
    }';
    df -Pki 2>/dev/null | awk 'NR>1 {print "DF|" $0}';
  ) | awk '
    /^MNT\|/ {
      s = substr($0, 5);
      p = index(s, "|");
      if (p > 0) fstype[substr(s, 1, p-1)] = substr(s, p+1);
      next;
    }
    /^DF\|/ {
      line = substr($0, 4);
      sub(/^[ \t]+/, "", line);
      n = split(line, f, /[ \t]+/);
      if (n < 9) next;
      dev = f[1];
      if (dev == "map" || dev == "devfs") next;
      if (f[2] !~ /^[0-9]+$/ || f[3] !~ /^[0-9]+$/ || f[4] !~ /^[0-9]+$/ || f[5] !~ /^[0-9]+%$/) next;
      tot = f[2]+0; used = f[3]+0; av = f[4]+0; cap = f[5];
      mnt = f[9];
      for (i=10; i<=n; i++) mnt = mnt " " f[i];
      fst = fstype[mnt];
      if (fst == "") fst = (dev ~ /^\/dev\/disk/ ? "apfs" : "unknown");
      if (fst ~ /^(devfs|autofs|fdesc|procfs|nullfs|tmpfs|mtmfs|lifs)$/) next;
      if (mnt ~ /^\/System\/Volumes\// || mnt == "/dev" || mnt ~ /^\/Library\/Developer\// || mnt ~ /^\/private\/var\/vm/) next;
      if (mnt == "/" && fst == "apfs" && tot > 0 && av >= 0 && (tot - av) > used) {
        used = tot - av;
        cap = sprintf("%d%%", int(used * 100 / tot + 0.5));
      }
      printf "FS=%s|%s|%.0f|%.0f|%.0f|%s|%s\n", dev, fst, tot, used, av, cap, mnt;
    }'
else
  df -PTk 2>/dev/null | awk 'NR>1 {
    if (NF==6) { dev="none"; fst=$1; tot=$2; used=$3; av=$4; cap=$5; mnt=$6 }
    else if (NF>=7) { dev=$1; fst=$2; tot=$3; used=$4; av=$5; cap=$6; mnt=$7 }
    else next;
    if (fst !~ /^(tmpfs|devtmpfs|squashfs|overlay|proc|sysfs|cgroup|cgroup2|nsfs|tracefs|efivarfs|autofs|mqueue|hugetlbfs|debugfs|pstore|securityfs|configfs|fusectl|fuse\.portal|ramfs)$/)
      printf "FS=%s|%s|%s|%s|%s|%s|%s\n", dev, fst, tot, used, av, cap, mnt
  }'
fi
echo "===SNS_SEC:INODE==="
if [ "$SNS_OS" = "Darwin" ]; then
  df -Pki 2>/dev/null | awk 'NR>1 {
    if ($1 == "map" || $1 == "devfs") next;
    if (NF < 9 || $5 !~ /^[0-9]+%$/) next;
    ipct = $8;
    if (ipct !~ /^[0-9]+%$/) ipct = "0%";
    mnt = $9;
    for (i=10; i<=NF; i++) mnt = mnt " " $i;
    if (mnt == "/System/Volumes/Data") { data_ipct = ipct; next }
    if (mnt ~ /^\/System\/Volumes\// || mnt == "/dev" || mnt ~ /^\/Library\/Developer\// || mnt ~ /^\/private\/var\/vm/) next;
    if (mnt == "/") { root_ipct = ipct; has_root = 1; next }
    printf "INODE=%s|%s\n", mnt, ipct;
  } END {
    if (has_root) {
      r = root_ipct + 0; d = data_ipct + 0;
      printf "INODE=/|%s\n", (d > r ? data_ipct : root_ipct);
    }
  }'
else
  df -Pi 2>/dev/null | awk 'NR>1 {
    if (NF==5) printf "INODE=%s|%s\n", $5, $4;
    else if (NF>=6) printf "INODE=%s|%s\n", $6, $5;
  }'
fi
`)

	// Interface IPv4 & Link States + Kernel TCP/UDP Socket State Matrix
	b.WriteString(`echo "===SNS_SEC:IFACE==="
if [ "$SNS_OS" = "Darwin" ]; then
  ifconfig 2>/dev/null | awk '
    /^[a-zA-Z0-9._-]+:/ {
      if (dev != "") {
        printf "OPER=%s|%s\n", dev, (st != "" ? st : (up ? "up" : "down"));
      }
      dev = $1; sub(/:$/, "", dev);
      up = ($0 ~ /<[^>]*UP[^>]*>/ && $0 ~ /<[^>]*RUNNING[^>]*>/) ? 1 : 0;
      st = "";
      next;
    }
    dev != "" && $1 == "inet" && $2 != "" {
      printf "IP4=%s|%s\n", dev, $2;
    }
    dev != "" && $1 == "status:" {
      if ($2 == "active") st = "up";
      else st = "down";
    }
    END {
      if (dev != "") {
        printf "OPER=%s|%s\n", dev, (st != "" ? st : (up ? "up" : "down"));
      }
    }'
else
  ip -4 -o addr show 2>/dev/null | awk '{split($4,a,"/"); printf "IP4=%s|%s\n", $2, a[1]}'
  for devp in /sys/class/net/*; do
    [ -e "$devp/operstate" ] || continue
    dn=$(basename "$devp")
    st=$(cat "$devp/operstate" 2>/dev/null)
    printf "OPER=%s|%s\n" "$dn" "$st"
  done
fi
echo "===SNS_SEC:SOCK==="
if [ "$SNS_OS" = "Darwin" ]; then
  netstat -an -p tcp 2>/dev/null | awk '$1 ~ /^tcp/ {
    st = $NF;
    if (st == "ESTABLISHED") c["01"]++;
    else if (st == "SYN_RCVD" || st == "SYN_RECEIVED") c["03"]++;
    else if (st == "TIME_WAIT") c["06"]++;
    else if (st == "CLOSE_WAIT") c["08"]++;
    else if (st == "LISTEN") c["0A"]++;
  } END { for (k in c) printf "TCP_%s=%d\n", k, c[k] }'
  UDP_CNT=$(netstat -an -p udp 2>/dev/null | awk '$1 ~ /^udp/ {c++} END {print c+0}')
  printf "UDP_ALL=%s\n" "${UDP_CNT:-0}"
else
  awk 'FNR>1 {st[$4]++} END {for (k in st) printf "TCP_%s=%d\n", k, st[k]}' /proc/net/tcp /proc/net/tcp6 2>/dev/null
  UDP_CNT=$(awk 'FNR>1 {c++} END {print c+0}' /proc/net/udp /proc/net/udp6 2>/dev/null)
  printf "UDP_ALL=%s\n" "${UDP_CNT:-0}"
fi
`)

	// Process States & Top CPU / Memory Processes
	if settings.CollectProcesses {
		b.WriteString(`echo "===SNS_SEC:PROC==="
if [ "$SNS_OS" = "Darwin" ]; then
  ps -axo stat= 2>/dev/null | awk '{
    tot++;
    c=substr($1,1,1);
    if (c=="R") run++;
    else if (c=="Z") zom++;
    else if (c=="U" || c=="D") blk++;
    else slp++;
  } END {printf "PSTAT=%d %d %d %d %d\n", tot+0, run+0, slp+0, zom+0, blk+0}'
  ps -axr -o pid=,user=,pcpu=,pmem=,rss=,stat=,etime=,comm= 2>/dev/null | head -n 8 | awk '$1 ~ /^[0-9]+$/ {
    cmd=$8; for (i=9; i<=NF; i++) cmd = cmd " " $i;
    sub(/^.*\//, "", cmd);
    printf "TOP_CPU=%s|%s|%s|%s|%s|%s|%s|%s\n", $1, $2, $3, $4, $5, $6, $7, cmd
  }'
  ps -axm -o pid=,user=,pcpu=,pmem=,rss=,stat=,etime=,comm= 2>/dev/null | head -n 8 | awk '$1 ~ /^[0-9]+$/ {
    cmd=$8; for (i=9; i<=NF; i++) cmd = cmd " " $i;
    sub(/^.*\//, "", cmd);
    printf "TOP_MEM=%s|%s|%s|%s|%s|%s|%s|%s\n", $1, $2, $3, $4, $5, $6, $7, cmd
  }'
else
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
fi
`)
	}

	// Listening Ports, Systemd/Launchd Services, and Docker Containers
	if settings.CollectPortsAndServices {
		b.WriteString(`echo "===SNS_SEC:PORTS==="
if [ "$SNS_OS" = "Darwin" ]; then
  (
    ps -axo pid=,comm= 2>/dev/null | awk '$1 ~ /^[0-9]+$/ {
      pid=$1; cmd=$2; for(i=3;i<=NF;i++) cmd=cmd " " $i;
      sub(/^.*\//, "", cmd); gsub(/"/, "", cmd);
      printf "P|%s|%s\n", pid, cmd;
    }';
    lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {
      cmd=$1; pid=$2; ep=$(NF-1);
      if ($(NF) != "(LISTEN)") ep=$NF;
      sub(/^.*\//, "", cmd); gsub(/"/, "", cmd);
      if (match(ep, /:[0-9]+$/)) {
        port = substr(ep, RSTART+1);
        printf "L|tcp|%s|%s|%s\n", port, pid, cmd;
      }
    }';
    netstat -anv -p tcp 2>/dev/null | awk '$1 ~ /^tcp/ && $6 == "LISTEN" {print "T|" $0}';
    netstat -anv -p udp 2>/dev/null | awk '$1 ~ /^udp/ && $5 == "*.*" {print "U|" $0}';
  ) | awk '
    function format_ep(proto, raw,   i, dot, host, port) {
      dot = 0;
      for (i = length(raw); i >= 1; i--) {
        if (substr(raw, i, 1) == ".") { dot = i; break }
      }
      if (dot <= 1) return "";
      host = substr(raw, 1, dot - 1);
      port = substr(raw, dot + 1);
      if (port !~ /^[0-9]+$/ || port+0 <= 0) return "";
      if (host == "*") {
        return (proto == "tcp6" || proto == "udp6") ? "[::]:" port : "0.0.0.0:" port;
      }
      if (index(host, ":") > 0) return "[" host "]:" port;
      return host ":" port;
    }
    function extract_pid_proc(f, nf, start_idx,   i, pid, proc, parts) {
      pid = 0; proc = "";
      if (start_idx <= nf && f[start_idx] ~ /^[0-9]+$/ && f[start_idx]+0 > 0) {
        pid = f[start_idx]+0;
      }
      for (i = start_idx; i <= nf; i++) {
        if (f[i] ~ /^[A-Za-z0-9_.-]+:[0-9]+$/ && f[i] !~ /^0x/) {
          split(f[i], parts, ":");
          if (parts[2]+0 > 0) {
            if (pid == 0) pid = parts[2]+0;
            proc = parts[1];
            break;
          }
        }
      }
      if (pid > 0 && pcomm[pid] != "") proc = pcomm[pid];
      return pid "|" proc;
    }
    /^P\|/ {
      s = substr($0, 3); p = index(s, "|");
      if (p > 0) pcomm[substr(s, 1, p-1)+0] = substr(s, p+1);
      next;
    }
    /^L\|/ {
      split($0, a, "|");
      if (a[3] != "" && lsof_cmd[a[3]] == "") {
        lsof_pid[a[3]] = a[4]; lsof_cmd[a[3]] = a[5];
      }
      next;
    }
    /^T\|/ {
      line = substr($0, 3);
      nf = split(line, f, /[ \t]+/);
      if (nf < 6) next;
      proto = (f[1] == "tcp6") ? "tcp6" : "tcp";
      ep = format_ep(proto, f[4]);
      if (ep == "") next;
      pp = extract_pid_proc(f, nf, 9);
      split(pp, pr, "|");
      pid = pr[1]+0; proc = pr[2];
      port = ep; sub(/.*:/, "", port);
      if (proc == "" && lsof_cmd[port] != "") {
        proc = lsof_cmd[port]; pid = lsof_pid[port]+0;
      }
      if (proc != "") printf "%s LISTEN 0 0 %s 0.0.0.0:* users:((\"%s\",pid=%d))\n", proto, ep, proc, pid;
      else printf "%s LISTEN 0 0 %s 0.0.0.0:*\n", proto, ep;
      next;
    }
    /^U\|/ {
      line = substr($0, 3);
      nf = split(line, f, /[ \t]+/);
      if (nf < 5) next;
      proto = (f[1] == "udp6") ? "udp6" : "udp";
      ep = format_ep(proto, f[4]);
      if (ep == "") next;
      pp = extract_pid_proc(f, nf, 8);
      split(pp, pr, "|");
      pid = pr[1]+0; proc = pr[2];
      if (proc != "") printf "%s UNCONN 0 0 %s 0.0.0.0:* users:((\"%s\",pid=%d))\n", proto, ep, proc, pid;
      else printf "%s UNCONN 0 0 %s 0.0.0.0:*\n", proto, ep;
      next;
    }
  ' | head -n 80
else
  if command -v ss >/dev/null 2>&1; then
    ss -tulnpH 2>/dev/null | head -n 80
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tulnp 2>/dev/null | awk 'NR>2' | head -n 80
  fi
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
		b.WriteString("if [ \"$SNS_OS\" = \"Darwin\" ]; then\n")
		b.WriteString("  LC_LIST=$(launchctl list 2>/dev/null || true)\n")
		b.WriteString("  printf \"%s\\n\" \"$LC_LIST\" | awk '$1 == \"-\" && $2 ~ /^[1-9][0-9]*$/ && $3 ~ /^homebrew\\.mxcl\\./ { n=$3; sub(/^homebrew\\.mxcl\\./, \"\", n); printf \"FAILED_UNIT=%s\\n\", n }' | head -n 15\n")
		b.WriteString("  SEEN_SVCS=\" \"\n")
		if len(watchedClean) > 0 {
			b.WriteString("  for u in " + strings.Join(watchedClean, " ") + "; do\n")
			b.WriteString("    SEEN_SVCS=\"$SEEN_SVCS$u \"\n")
			b.WriteString("    st=$(printf \"%s\\n\" \"$LC_LIST\" | awk -v t=\"$u\" '($3 == t || $3 == \"homebrew.mxcl.\" t) { if ($1 ~ /^[0-9]+$/) print \"active\"; else if ($2 ~ /^[1-9][0-9]*$/) print \"failed\"; else print \"inactive\"; exit }')\n")
			b.WriteString("    if [ -z \"$st\" ] || [ \"$st\" != \"active\" ]; then\n")
			b.WriteString("      if [ \"$u\" = \"docker\" ] && docker info >/dev/null 2>&1; then st=\"active\";\n")
			b.WriteString("      elif pgrep -x \"$u\" >/dev/null 2>&1; then st=\"active\"; fi\n")
			b.WriteString("    fi\n")
			b.WriteString("    [ -z \"$st\" ] && st=\"not-found\"\n")
			b.WriteString("    printf \"SVC=%s|%s|watched\\n\" \"$u\" \"$st\"\n")
			b.WriteString("  done\n")
		}
		b.WriteString(`  for line in $(printf "%s\n" "$LC_LIST" | awk '$3 ~ /^homebrew\.mxcl\./ { n=$3; sub(/^homebrew\.mxcl\./, "", n); st=($1 ~ /^[0-9]+$/ ? "active" : ($2 ~ /^[1-9][0-9]*$/ ? "failed" : "inactive")); printf "%s|%s\n", n, st }' | head -n 20); do
    bn=${line%%|*}
    bst=${line#*|}
    case "$SEEN_SVCS" in *" $bn "*) continue ;; esac
    SEEN_SVCS="$SEEN_SVCS$bn "
    printf "SVC=%s|%s|auto\n" "$bn" "$bst"
  done
  for u in sshd nginx caddy postgres mysqld mariadbd redis-server tailscaled cloudflared; do
    case "$SEEN_SVCS" in *" $u "*) continue ;; esac
    if pgrep -x "$u" >/dev/null 2>&1; then
      SEEN_SVCS="$SEEN_SVCS$u "
      printf "SVC=%s|active|auto\n" "$u"
    fi
  done
  case "$SEEN_SVCS" in *" docker "*) ;; *)
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
      printf "SVC=docker|active|auto\n"
    fi
  ;; esac
else
`)
		b.WriteString("  if command -v systemctl >/dev/null 2>&1; then\n")
		b.WriteString("    systemctl --failed --no-legend --no-pager --plain 2>/dev/null | head -n 15 | awk '{printf \"FAILED_UNIT=%s\\n\", $1}'\n")
		if len(watchedClean) > 0 {
			b.WriteString("    for u in " + strings.Join(watchedClean, " ") + "; do\n")
			b.WriteString("      st=$(systemctl is-active \"$u\" 2>/dev/null || true)\n")
			b.WriteString("      [ -z \"$st\" ] && st=\"not-found\"\n")
			b.WriteString("      printf \"SVC=%s|%s|watched\\n\" \"$u\" \"$st\"\n")
			b.WriteString("    done\n")
		}
		if len(autoClean) > 0 {
			b.WriteString("    for u in " + strings.Join(autoClean, " ") + "; do\n")
			b.WriteString("      ld=$(systemctl show \"$u\" -p LoadState --value 2>/dev/null || true)\n")
			b.WriteString("      if [ \"$ld\" = \"loaded\" ]; then\n")
			b.WriteString("        st=$(systemctl is-active \"$u\" 2>/dev/null || echo inactive)\n")
			b.WriteString("        printf \"SVC=%s|%s|auto\\n\" \"$u\" \"$st\"\n")
			b.WriteString("      fi\n")
			b.WriteString("    done\n")
		}
		b.WriteString("  fi\n")
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
if [ "$SNS_OS" = "Darwin" ]; then
  who 2>/dev/null | head -n 12 | awk '{
    if (NF >= 6) printf "WHO=%s|%s|%s %s %s|%s\n", $1, $2, $3, $4, $5, $6;
    else if (NF >= 5) printf "WHO=%s|%s|%s %s %s|\n", $1, $2, $3, $4, $5;
  }'
  UID0_OUT=$(dscl . -list /Users UniqueID 2>/dev/null | awk '$2 == 0 {printf "UID0=%s\n", $1}')
  if [ -n "$UID0_OUT" ]; then
    printf "%s\n" "$UID0_OUT"
  elif [ -r /etc/passwd ]; then
    awk -F: '!/^#/ && $3 == "0" {printf "UID0=%s\n", $1}' /etc/passwd 2>/dev/null
  fi
  echo "REBOOT_REQ=0"
  FW_ST="unknown"; FW_DET=""
  if [ -x /usr/libexec/ApplicationFirewall/socketfilterfw ]; then
    ALF_OUT=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || true)
    if echo "$ALF_OUT" | grep -qi "enabled"; then FW_ST="active"; FW_DET="macos-alf";
    elif echo "$ALF_OUT" | grep -qi "disabled"; then FW_ST="inactive"; FW_DET="macos-alf"; fi
  fi
  if [ "$FW_ST" = "unknown" ]; then
    ALF_V=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null || true)
    if [ "$ALF_V" = "1" ] || [ "$ALF_V" = "2" ]; then FW_ST="active"; FW_DET="macos-alf";
    elif [ "$ALF_V" = "0" ]; then FW_ST="inactive"; FW_DET="macos-alf"; fi
  fi
  printf "FW=%s|%s\n" "$FW_ST" "$FW_DET"
  if command -v csrutil >/dev/null 2>&1; then
    SIP_OUT=$(csrutil status 2>/dev/null || true)
    if echo "$SIP_OUT" | grep -qi "disabled"; then printf "MAC=SIP:disabled\n"
    elif echo "$SIP_OUT" | grep -qi "enabled"; then printf "MAC=SIP:enabled\n"
    fi
  fi
  SSH_LOG=""
  if command -v log >/dev/null 2>&1; then
    SSH_LOG=$(log show --style syslog --last 1h --predicate '(processImagePath ENDSWITH "/sshd" OR processImagePath ENDSWITH "/sshd-session") AND (eventMessage CONTAINS "Failed password" OR eventMessage CONTAINS "Invalid user")' 2>/dev/null | tail -n 600 || true)
  fi
  if [ -n "$SSH_LOG" ]; then
    FAIL_CNT=$(printf "%s\n" "$SSH_LOG" | grep -c . || echo 0)
    printf "SSH_FAIL_CNT=%s\n" "$FAIL_CNT"
    printf "%s\n" "$SSH_LOG" | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{c[$2]++} END {for (ip in c) printf "%d %s\n", c[ip], ip}' | sort -rn | head -n 5 | awk '{printf "SSH_FAIL_IP=%s(%s)\n", $2, $1}'
  else
    echo "SSH_FAIL_CNT=0"
  fi
else
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
fi
`)
	}

	// Ensure >= 250ms delta (Linux) or 1s top sample window (Darwin) before T1 sample
	b.WriteString("if [ \"$SNS_OS\" = \"Darwin\" ]; then\n")
	b.WriteString(`  CPU_PCT_VAL=$(top -F -R -l 2 -n 0 -s 1 2>/dev/null | awk '/^CPU usage:/ {
    u=0; s=0; id=0;
    for (i=1; i<=NF; i++) {
      if ($(i+1) ~ /^user/) { v=$i; gsub(/%/,"",v); u=v+0 }
      else if ($(i+1) ~ /^sys/) { v=$i; gsub(/%/,"",v); s=v+0 }
      else if ($(i+1) ~ /^idle/) { v=$i; gsub(/%/,"",v); id=v+0 }
    }
    tot = 100.0 - id; if (tot < 0) tot = 0; if (tot > 100) tot = 100;
    last = sprintf("%.2f %.2f %.2f 0 0", tot, u, s);
  } END { if (last != "") print last }')
  if [ -z "$CPU_PCT_VAL" ]; then
    CPU_PCT_VAL=$(iostat -C -w 1 -c 2 2>/dev/null | awk 'NF>=3 && $(NF-2) ~ /^[0-9]+$/ && $(NF-1) ~ /^[0-9]+$/ && $NF ~ /^[0-9]+$/ {
      u=$(NF-2)+0; s=$(NF-1)+0; id=$NF+0; tot=100-id; if(tot<0)tot=0; if(tot>100)tot=100;
      last = sprintf("%.2f %.2f %.2f 0 0", tot, u, s);
    } END { if (last != "") print last }')
  fi
  echo "===SNS_SEC:SAMPLE_T1==="
`)
	b.WriteString(darwinCounterSampleBlock)
	b.WriteString(`  [ -n "$CPU_PCT_VAL" ] && printf "CPU_PCT=%s\n" "$CPU_PCT_VAL"
else
  sleep 0.25 2>/dev/null || sleep 1
  echo "===SNS_SEC:SAMPLE_T1==="
  [ -r /proc/uptime ] && awk '{printf "UP=%s\n", $1}' /proc/uptime
  [ -r /proc/stat ] && awk '/^cpu / {print "CPU=" $0} /^ctxt / {print "CTXT=" $2}' /proc/stat
  [ -r /proc/net/dev ] && awk 'NR>2 {gsub(/:/, " "); printf "NET=%s %s %s %s %s %s %s %s %s\n", $1, $2, $3, $4, $5, $10, $11, $12, $13}' /proc/net/dev
  [ -r /proc/diskstats ] && awk '$3 ~ /^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+|dm-[0-9]+)$/ {printf "BIO=%s %s %s %s %s\n", $3, $4, $6, $8, $10}' /proc/diskstats
fi
true
`)
	return b.String()
}
