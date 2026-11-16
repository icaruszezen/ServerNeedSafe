package vault

import "time"

// AuthType defines how an SSH server authenticates.
type AuthType string

const (
	AuthPassword   AuthType = "password"
	AuthPrivateKey AuthType = "private_key"
	AuthCredential AuthType = "credential" // References a reusable item in VaultState.Credentials
)

// HostKeyPolicy controls SSH host key verification behavior.
type HostKeyPolicy string

const (
	HostKeyAskNew HostKeyPolicy = "ask_new" // Prompt user on unknown or changed host key (strict interactive)
	HostKeyTOFU   HostKeyPolicy = "tofu"    // Trust On First Use automatically, block if fingerprint changes
)

// VaultStatus represents the lifecycle state of the encrypted vault.
type VaultStatus string

const (
	StatusUninitialized VaultStatus = "uninitialized"
	StatusLocked        VaultStatus = "locked"
	StatusUnlocked      VaultStatus = "unlocked"
)

// ServerConfig stores complete connection and metadata for a managed SSH server.
// Every field resides strictly inside the encrypted VaultState payload.
type ServerConfig struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Group              string    `json:"group"`
	Tags               []string  `json:"tags"`
	Host               string    `json:"host"`
	Port               int       `json:"port"`
	Username           string    `json:"username"`
	AuthType           AuthType  `json:"auth_type"`
	Password           string    `json:"password,omitempty"`
	PrivateKey         string    `json:"private_key,omitempty"`
	Passphrase         string    `json:"passphrase,omitempty"`
	CredentialID       string    `json:"credential_id,omitempty"`
	JumpServerID       string    `json:"jump_server_id,omitempty"` // Optional SSH Bastion / ProxyJump server ID
	DefaultPath        string    `json:"default_path,omitempty"`   // Default initial SFTP / shell directory
	Notes              string    `json:"notes,omitempty"`
	Pinned             bool      `json:"pinned"`
	KeepAliveSec       int       `json:"keep_alive_sec"`
	LastConnectedAt    *time.Time `json:"last_connected_at,omitempty"`
	LastLatencyMs      int64     `json:"last_latency_ms,omitempty"`
	LastOSInfo         string    `json:"last_os_info,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// ServerView is a redacted representation returned to list views so raw secrets
// are never unnecessarily transmitted over HTTP JSON responses unless explicitly needed internally.
type ServerView struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Group           string     `json:"group"`
	Tags            []string   `json:"tags"`
	Host            string     `json:"host"`
	Port            int        `json:"port"`
	Username        string     `json:"username"`
	AuthType        AuthType   `json:"auth_type"`
	HasPassword     bool       `json:"has_password"`
	HasPrivateKey   bool       `json:"has_private_key"`
	HasPassphrase   bool       `json:"has_passphrase"`
	CredentialID    string     `json:"credential_id,omitempty"`
	JumpServerID    string     `json:"jump_server_id,omitempty"`
	DefaultPath     string     `json:"default_path,omitempty"`
	Notes           string     `json:"notes,omitempty"`
	Pinned          bool       `json:"pinned"`
	KeepAliveSec    int        `json:"keep_alive_sec"`
	LastConnectedAt *time.Time `json:"last_connected_at,omitempty"`
	LastLatencyMs   int64      `json:"last_latency_ms,omitempty"`
	LastOSInfo      string     `json:"last_os_info,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func (s ServerConfig) ToView() ServerView {
	tags := s.Tags
	if tags == nil {
		tags = []string{}
	}
	return ServerView{
		ID:              s.ID,
		Name:            s.Name,
		Group:           s.Group,
		Tags:            tags,
		Host:            s.Host,
		Port:            s.Port,
		Username:        s.Username,
		AuthType:        s.AuthType,
		HasPassword:     s.Password != "",
		HasPrivateKey:   s.PrivateKey != "",
		HasPassphrase:   s.Passphrase != "",
		CredentialID:    s.CredentialID,
		JumpServerID:    s.JumpServerID,
		DefaultPath:     s.DefaultPath,
		Notes:           s.Notes,
		Pinned:          s.Pinned,
		KeepAliveSec:    s.KeepAliveSec,
		LastConnectedAt: s.LastConnectedAt,
		LastLatencyMs:   s.LastLatencyMs,
		LastOSInfo:      s.LastOSInfo,
		CreatedAt:       s.CreatedAt,
		UpdatedAt:       s.UpdatedAt,
	}
}

// Credential stores a reusable SSH identity (password or SSH key pair) inside the encrypted keychain.
type Credential struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Kind          AuthType  `json:"kind"` // "password" or "private_key"
	UsernameHint  string    `json:"username_hint,omitempty"`
	Password      string    `json:"password,omitempty"`
	PrivateKey    string    `json:"private_key,omitempty"`
	Passphrase    string    `json:"passphrase,omitempty"`
	PublicKey     string    `json:"public_key,omitempty"`
	Fingerprint   string    `json:"fingerprint,omitempty"`
	KeyAlgorithm  string    `json:"key_algorithm,omitempty"`
	Notes         string    `json:"notes,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// CredentialView omits raw secret material when listing keychain entries.
type CredentialView struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Kind         AuthType  `json:"kind"`
	UsernameHint string    `json:"username_hint,omitempty"`
	HasPassword  bool      `json:"has_password"`
	HasPrivateKey bool     `json:"has_private_key"`
	HasPassphrase bool     `json:"has_passphrase"`
	PublicKey    string    `json:"public_key,omitempty"`
	Fingerprint  string    `json:"fingerprint,omitempty"`
	KeyAlgorithm string    `json:"key_algorithm,omitempty"`
	Notes        string    `json:"notes,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (c Credential) ToView() CredentialView {
	return CredentialView{
		ID:            c.ID,
		Name:          c.Name,
		Kind:          c.Kind,
		UsernameHint:  c.UsernameHint,
		HasPassword:   c.Password != "",
		HasPrivateKey: c.PrivateKey != "",
		HasPassphrase: c.Passphrase != "",
		PublicKey:     c.PublicKey,
		Fingerprint:   c.Fingerprint,
		KeyAlgorithm:  c.KeyAlgorithm,
		Notes:         c.Notes,
		CreatedAt:     c.CreatedAt,
		UpdatedAt:     c.UpdatedAt,
	}
}

// Snippet represents a reusable operational or security inspection command.
type Snippet struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Category    string    `json:"category"`
	Command     string    `json:"command"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// KnownHost records a trusted SSH host public key fingerprint inside the encrypted vault.
type KnownHost struct {
	Address       string    `json:"address"`        // host:port
	ServerName    string    `json:"server_name"`    // friendly hint
	KeyType       string    `json:"key_type"`       // e.g. ssh-ed25519
	Fingerprint   string    `json:"fingerprint"`    // SHA256:...
	PublicKeyB64  string    `json:"public_key_b64"` // wire format base64
	FirstSeenAt   time.Time `json:"first_seen_at"`
	LastVerifiedAt time.Time `json:"last_verified_at"`
}

// AuditEntry logs security-relevant operations inside the encrypted vault.
type AuditEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"` // e.g. vault.unlock, ssh.connect, sftp.upload, key.generate
	Target    string    `json:"target,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	ClientIP  string    `json:"client_ip,omitempty"`
	Success   bool      `json:"success"`
}

// AppSettings stores all user preferences inside the encrypted vault.
type AppSettings struct {
	AutoLockMinutes   int           `json:"auto_lock_minutes"`    // 0 = disabled, default 30
	HostKeyPolicy     HostKeyPolicy `json:"host_key_policy"`      // "tofu" or "ask_new"
	TerminalFontSize  int           `json:"terminal_font_size"`   // default 14
	TerminalScrollback int          `json:"terminal_scrollback"`  // default 5000
	ShowHiddenFiles   bool          `json:"show_hidden_files"`    // SFTP hidden files
}

// VaultState is the root plaintext structure serialized, compressed, padded,
// and encrypted via XChaCha20-Poly1305 into vault.sns.
type VaultState struct {
	SchemaVersion int            `json:"schema_version"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	Groups        []string       `json:"groups"`
	Servers       []ServerConfig `json:"servers"`
	Credentials   []Credential   `json:"credentials"`
	Snippets      []Snippet      `json:"snippets"`
	KnownHosts    []KnownHost    `json:"known_hosts"`
	AuditLogs     []AuditEntry   `json:"audit_logs"`
	Settings      AppSettings    `json:"settings"`
}

// DefaultVaultState initializes a clean vault with practical default groups and security inspection snippets.
func DefaultVaultState() *VaultState {
	now := time.Now().UTC()
	return &VaultState{
		SchemaVersion: 1,
		CreatedAt:     now,
		UpdatedAt:     now,
		Groups: []string{
			"生产环境",
			"核心数据库",
			"测试与预发",
			"边缘与网关",
		},
		Servers:     []ServerConfig{},
		Credentials: []Credential{},
		Snippets: []Snippet{
			{
				ID:          "snip-sec-ports",
				Title:       "监听端口与进程排查",
				Category:    "安全巡检",
				Command:     "ss -tulnp || netstat -tulnp",
				Description: "查看当前服务器所有监听的 TCP/UDP 端口及对应进程",
				CreatedAt:   now,
				UpdatedAt:   now,
			},
			{
				ID:          "snip-sec-ssh-fail",
				Title:       "SSH 登录失败与爆破审计",
				Category:    "安全巡检",
				Command:     "journalctl -u ssh -u sshd --no-pager -n 40 2>/dev/null || tail -n 40 /var/log/auth.log /var/log/secure 2>/dev/null",
				Description: "检查近期 SSH 认证日志中的异常暴力破解记录",
				CreatedAt:   now,
				UpdatedAt:   now,
			},
			{
				ID:          "snip-ops-sysinfo",
				Title:       "系统负载与磁盘概览",
				Category:    "日常运维",
				Command:     "uname -a && uptime && echo '--- MEMORY ---' && free -h && echo '--- DISK ---' && df -hT -x tmpfs -x devtmpfs",
				Description: "快速输出内核版本、运行时间、内存与磁盘容量状态",
				CreatedAt:   now,
				UpdatedAt:   now,
			},
			{
				ID:          "snip-sec-users",
				Title:       "特权账户与当前活跃会话",
				Category:    "安全巡检",
				Command:     "w && echo '--- UID 0 ACCOUNTS ---' && awk -F: '($3 == 0) {print $1}' /etc/passwd && echo '--- LAST LOGINS ---' && last -n 10",
				Description: "检查当前登录终端、UID=0 特权账号及最近登录历史",
				CreatedAt:   now,
				UpdatedAt:   now,
			},
		},
		KnownHosts: []KnownHost{},
		AuditLogs:  []AuditEntry{},
		Settings: AppSettings{
			AutoLockMinutes:    30,
			HostKeyPolicy:      HostKeyTOFU,
			TerminalFontSize:   14,
			TerminalScrollback: 5000,
			ShowHiddenFiles:    true,
		},
	}
}
