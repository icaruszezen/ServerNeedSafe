package updater

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/vault"
	"github.com/icaruszezen/ServerNeedSafe/internal/version"
)

// JobStage describes the current lifecycle stage of an in-progress self-update.
type JobStage string

const (
	StageIdle         JobStage = "idle"
	StageProbing      JobStage = "probing"
	StageDownloading  JobStage = "downloading"
	StageVerifying    JobStage = "verifying"
	StageSelfChecking JobStage = "self_checking"
	StageReplacing    JobStage = "replacing"
	StageRestarting   JobStage = "restarting"
	StageCompleted    JobStage = "completed"
	StageFailed       JobStage = "failed"
)

// UpdateJobState reports real-time progress for an initiated update operation.
type UpdateJobState struct {
	Stage           JobStage   `json:"stage"`
	TargetVersion   string     `json:"target_version,omitempty"`
	AssetName       string     `json:"asset_name,omitempty"`
	MirrorID        string     `json:"mirror_id,omitempty"`
	MirrorName      string     `json:"mirror_name,omitempty"`
	DownloadedBytes int64      `json:"downloaded_bytes"`
	TotalBytes      int64      `json:"total_bytes"`
	SpeedBps        int64      `json:"speed_bps"`
	ProgressPercent float64    `json:"progress_percent"`
	ExpectedSHA256  string     `json:"expected_sha256,omitempty"`
	ChecksumSource  string     `json:"checksum_source,omitempty"`
	Message         string     `json:"message,omitempty"`
	Error           string     `json:"error,omitempty"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
}

// UpdateOverview is the full status snapshot exposed to the Web UI.
type UpdateOverview struct {
	Current         version.Info           `json:"current"`
	Capabilities    Capabilities           `json:"capabilities"`
	Settings        vault.UpdateSettings   `json:"settings"`
	LatestRelease   *ReleaseInfo           `json:"latest_release,omitempty"`
	UpdateAvailable bool                   `json:"update_available"`
	Skipped         bool                   `json:"skipped"`
	Checking        bool                   `json:"checking"`
	LastCheckedAt   *time.Time             `json:"last_checked_at,omitempty"`
	NextCheckAt     *time.Time             `json:"next_check_at,omitempty"`
	LastError       string                 `json:"last_error,omitempty"`
	ActiveMirror    *MirrorProbeResult     `json:"active_mirror,omitempty"`
	Mirrors         []MirrorProbeResult    `json:"mirrors"`
	BuiltinMirrors  []MirrorNode           `json:"builtin_mirrors"`
	Job             UpdateJobState         `json:"job"`
	DockerCommands  *DockerUpgradeCommands `json:"docker_commands,omitempty"`
}

// Config configures the release checker & auto-updater service.
type Config struct {
	DeployMode      string
	Store           *vault.Store
	ActiveSSHCount  func() int
	OnRestart       func(exePath, backupPath string) error
	RepoSlug        string
	GitHubBaseURL   string
	GitHubAPIBase   string
	BuiltinMirrors  []MirrorNode
	HTTPClient      *http.Client
	DownloadClient  *http.Client
	CurrentVersion  string
	ExecutablePath  string
	InDocker        *bool
	SelfCheckFunc   func(ctx context.Context, binaryPath, expectedTag string) error
	ReplaceFunc     func(exePath, stagedPath string) (string, error)
	StartupDelay    time.Duration
	DisableAutoLoop bool
}

// Service manages background release detection, China mirror probing, and safe self-updates.
type Service struct {
	cfg Config

	mu            sync.RWMutex
	latestRelease *ReleaseInfo
	lastCheckedAt *time.Time
	nextCheckAt   *time.Time
	lastError     string
	checking      bool
	activeMirror  *MirrorProbeResult
	mirrors       []MirrorProbeResult
	job           UpdateJobState

	stopCh  chan struct{}
	wakeCh  chan struct{}
	closeMu sync.Once
}

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          16,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   8 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
		},
	}
}

// NewService creates a new Updater Service.
func NewService(cfg Config) *Service {
	if cfg.DeployMode == "" {
		cfg.DeployMode = "server"
	}
	if cfg.RepoSlug == "" {
		cfg.RepoSlug = version.RepoSlug
	}
	if cfg.GitHubBaseURL == "" {
		cfg.GitHubBaseURL = "https://github.com"
	}
	if cfg.GitHubAPIBase == "" {
		cfg.GitHubAPIBase = "https://api.github.com"
	}
	if len(cfg.BuiltinMirrors) == 0 {
		cfg.BuiltinMirrors = DefaultBuiltinMirrors()
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = newHTTPClient(12 * time.Second)
	}
	if cfg.DownloadClient == nil {
		// Longer timeout for large binary downloads (no whole-request timeout; rely on context & header timeout).
		cfg.DownloadClient = &http.Client{
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				MaxIdleConns:          8,
				IdleConnTimeout:       30 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 20 * time.Second,
			},
		}
	}
	if cfg.ExecutablePath == "" {
		cfg.ExecutablePath = resolveCurrentExecutable()
	}
	if cfg.SelfCheckFunc == nil {
		cfg.SelfCheckFunc = defaultSelfCheckBinary
	}
	if cfg.ReplaceFunc == nil {
		cfg.ReplaceFunc = StageAndReplaceBinary
	}
	if cfg.StartupDelay <= 0 {
		cfg.StartupDelay = 18 * time.Second
	}

	return &Service{
		cfg: cfg,
		job: UpdateJobState{
			Stage: StageIdle,
		},
		stopCh: make(chan struct{}),
		wakeCh: make(chan struct{}, 1),
	}
}

// Start launches the background periodic release check loop.
func (s *Service) Start() {
	if s.cfg.DisableAutoLoop {
		return
	}
	go s.runLoop()
}

// Close terminates the background release check loop.
func (s *Service) Close() {
	s.closeMu.Do(func() {
		close(s.stopCh)
	})
}

// NotifySettingsUpdated wakes the background scheduler after user settings changes.
func (s *Service) NotifySettingsUpdated() {
	select {
	case s.wakeCh <- struct{}{}:
	default:
	}
}

func (s *Service) currentVersionInfo() version.Info {
	info := version.Current()
	if strings.TrimSpace(s.cfg.CurrentVersion) != "" {
		info.Version = strings.TrimSpace(s.cfg.CurrentVersion)
		info.IsDev = version.IsDevVersion(info.Version)
	}
	return info
}

func (s *Service) inDocker() bool {
	if s.cfg.InDocker != nil {
		return *s.cfg.InDocker
	}
	return DetectInDocker()
}

func (s *Service) currentSettings() vault.UpdateSettings {
	if s.cfg.Store != nil {
		return s.cfg.Store.GetUpdateSettings()
	}
	return vault.DefaultUpdateSettings()
}

func (s *Service) runLoop() {
	// Wait briefly after boot so critical SSH/Monitor services settle first.
	initTimer := time.NewTimer(s.cfg.StartupDelay)
	defer initTimer.Stop()

	select {
	case <-s.stopCh:
		return
	case <-initTimer.C:
	case <-s.wakeCh:
	}

	for {
		settings := s.currentSettings()
		autoOn := settings.AutoCheckEnabled == nil || *settings.AutoCheckEnabled
		interval := time.Duration(settings.CheckIntervalHours) * time.Hour
		if interval < time.Hour {
			interval = 6 * time.Hour
		}

		if autoOn {
			s.mu.RLock()
			last := s.lastCheckedAt
			s.mu.RUnlock()

			shouldCheck := last == nil || time.Since(*last) >= interval
			if shouldCheck {
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				_, _ = s.CheckNow(ctx, false)
				cancel()
			}

			next := time.Now().UTC().Add(interval)
			s.mu.Lock()
			s.nextCheckAt = &next
			s.mu.Unlock()

			timer := time.NewTimer(interval)
			select {
			case <-s.stopCh:
				timer.Stop()
				return
			case <-s.wakeCh:
				timer.Stop()
			case <-timer.C:
			}
		} else {
			s.mu.Lock()
			s.nextCheckAt = nil
			s.mu.Unlock()

			select {
			case <-s.stopCh:
				return
			case <-s.wakeCh:
			}
		}
	}
}

// Status returns a complete, thread-safe snapshot of update status, mirrors, capabilities, and job state.
func (s *Service) Status() UpdateOverview {
	cur := s.currentVersionInfo()
	settings := s.currentSettings()
	caps := DetectCapabilities(s.cfg.DeployMode, cur.Version, s.cfg.ExecutablePath, s.inDocker())

	s.mu.RLock()
	defer s.mu.RUnlock()

	var latestCopy *ReleaseInfo
	if s.latestRelease != nil {
		cp := *s.latestRelease
		if len(s.latestRelease.Assets) > 0 {
			cp.Assets = make([]ReleaseAsset, len(s.latestRelease.Assets))
			copy(cp.Assets, s.latestRelease.Assets)
		}
		latestCopy = &cp
	}

	var activeMirrorCopy *MirrorProbeResult
	if s.activeMirror != nil {
		cp := *s.activeMirror
		activeMirrorCopy = &cp
	}

	mirrorsCopy := make([]MirrorProbeResult, len(s.mirrors))
	copy(mirrorsCopy, s.mirrors)

	builtinCopy := make([]MirrorNode, len(s.cfg.BuiltinMirrors))
	copy(builtinCopy, s.cfg.BuiltinMirrors)

	updateAvailable := false
	skipped := false
	if latestCopy != nil {
		updateAvailable = IsNewerVersion(latestCopy.TagName, cur.Version)
		if settings.SkippedVersion != "" && strings.EqualFold(settings.SkippedVersion, latestCopy.TagName) {
			skipped = true
		}
	}

	var dockerCmds *DockerUpgradeCommands
	if caps.InDocker {
		tag := "latest"
		if latestCopy != nil && latestCopy.TagName != "" {
			tag = latestCopy.TagName
		}
		dockerCmds = BuildDockerUpgradeCommands(tag)
	}

	var lastCheckedCopy, nextCheckCopy *time.Time
	if s.lastCheckedAt != nil {
		t := *s.lastCheckedAt
		lastCheckedCopy = &t
	}
	if s.nextCheckAt != nil {
		t := *s.nextCheckAt
		nextCheckCopy = &t
	}

	return UpdateOverview{
		Current:         cur,
		Capabilities:    caps,
		Settings:        settings,
		LatestRelease:   latestCopy,
		UpdateAvailable: updateAvailable,
		Skipped:         skipped,
		Checking:        s.checking,
		LastCheckedAt:   lastCheckedCopy,
		NextCheckAt:     nextCheckCopy,
		LastError:       s.lastError,
		ActiveMirror:    activeMirrorCopy,
		Mirrors:         mirrorsCopy,
		BuiltinMirrors:  builtinCopy,
		Job:             s.job,
		DockerCommands:  dockerCmds,
	}
}

// ProbeMirrorsNow concurrently benchmarks all candidate mirrors for the current mirror mode.
func (s *Service) ProbeMirrorsNow(ctx context.Context) []MirrorProbeResult {
	settings := s.currentSettings()
	candidates := ResolveCandidateMirrors(settings, s.cfg.BuiltinMirrors)
	results := ProbeMirrors(ctx, s.cfg.HTTPClient, s.cfg.GitHubBaseURL, s.cfg.RepoSlug, candidates)

	s.mu.Lock()
	s.mirrors = results
	for i := range results {
		if results[i].Reachable {
			cp := results[i]
			s.activeMirror = &cp
			break
		}
	}
	s.mu.Unlock()

	return results
}

// CheckNow probes/selects the fastest route and checks GitHub for the latest release.
func (s *Service) CheckNow(ctx context.Context, forceProbe bool) (UpdateOverview, error) {
	s.mu.Lock()
	if s.checking {
		s.mu.Unlock()
		return s.Status(), nil
	}
	s.checking = true
	cachedMirrors := make([]MirrorProbeResult, len(s.mirrors))
	copy(cachedMirrors, s.mirrors)
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.checking = false
		s.mu.Unlock()
	}()

	settings := s.currentSettings()
	candidates := ResolveCandidateMirrors(settings, s.cfg.BuiltinMirrors)

	// Re-probe mirrors if forced, empty, or stale (> 15 minutes) or mirror set changed.
	needProbe := forceProbe || len(cachedMirrors) == 0 || mirrorsStaleOrChanged(cachedMirrors, candidates)
	var probeResults []MirrorProbeResult
	if needProbe && len(candidates) > 1 {
		probeResults = ProbeMirrors(ctx, s.cfg.HTTPClient, s.cfg.GitHubBaseURL, s.cfg.RepoSlug, candidates)
	} else if needProbe && len(candidates) == 1 {
		probeResults = ProbeMirrors(ctx, s.cfg.HTTPClient, s.cfg.GitHubBaseURL, s.cfg.RepoSlug, candidates)
	} else {
		probeResults = cachedMirrors
	}

	orderedNodes := orderNodesByProbe(candidates, probeResults)
	rel, usedNode, err := FetchLatestRelease(
		ctx,
		s.cfg.HTTPClient,
		s.cfg.GitHubBaseURL,
		s.cfg.GitHubAPIBase,
		s.cfg.RepoSlug,
		settings.IncludePrerelease,
		settings.MirrorMode,
		orderedNodes,
	)

	now := time.Now().UTC()
	s.mu.Lock()
	s.lastCheckedAt = &now
	if len(probeResults) > 0 {
		s.mirrors = probeResults
	}
	if err != nil {
		s.lastError = err.Error()
		s.mu.Unlock()
		return s.Status(), err
	}

	s.latestRelease = rel
	s.lastError = ""
	if usedNode != nil {
		s.activeMirror = findProbeOrSynthesize(*usedNode, probeResults)
	}
	s.mu.Unlock()

	return s.Status(), nil
}

// StartUpdate validates preconditions and executes the download -> SHA-256 verify -> self-check -> replace -> restart pipeline asynchronously.
func (s *Service) StartUpdate(confirmDisconnectSSH bool, clientIP string) (UpdateOverview, int, error) {
	overview := s.Status()
	if !overview.Capabilities.CanSelfUpdate {
		return overview, 0, errors.New(overview.Capabilities.CannotUpdateReason)
	}
	if overview.LatestRelease == nil || overview.LatestRelease.TagName == "" {
		return overview, 0, errors.New("尚未检测到最新 Release 信息，请先点击「检查更新」")
	}
	if !overview.UpdateAvailable {
		return overview, 0, fmt.Errorf("当前版本 (%s) 已是最新，无需更新", overview.Current.Version)
	}

	activeSSH := 0
	if s.cfg.ActiveSSHCount != nil {
		activeSSH = s.cfg.ActiveSSHCount()
	}
	if activeSSH > 0 && !confirmDisconnectSSH {
		return overview, activeSSH, ErrActiveSSHSessions
	}

	s.mu.Lock()
	if isJobRunning(s.job.Stage) {
		s.mu.Unlock()
		return s.Status(), activeSSH, errors.New("已有自动更新任务正在进行中，请稍候")
	}
	now := time.Now().UTC()
	s.job = UpdateJobState{
		Stage:         StageProbing,
		TargetVersion: overview.LatestRelease.TagName,
		AssetName:     overview.Capabilities.AssetName,
		Message:       "正在探测最优国内加速线路...",
		StartedAt:     &now,
		UpdatedAt:     &now,
	}
	s.mu.Unlock()

	if s.cfg.Store != nil {
		s.cfg.Store.RecordAuditAsync(
			"system.update_start",
			overview.LatestRelease.TagName,
			fmt.Sprintf("管理员启动一键自动更新：%s -> %s (%s)", overview.Current.Version, overview.LatestRelease.TagName, overview.Capabilities.AssetName),
			clientIP,
			true,
		)
	}

	go s.executeUpdatePipeline(overview.LatestRelease, overview.Capabilities, clientIP)
	return s.Status(), activeSSH, nil
}

// ErrActiveSSHSessions signals that active interactive SSH tabs exist and require user confirmation.
var ErrActiveSSHSessions = errors.New("当前存在活跃的 SSH 终端会话，重启更新将断开连接")

func isJobRunning(st JobStage) bool {
	switch st {
	case StageProbing, StageDownloading, StageVerifying, StageSelfChecking, StageReplacing, StageRestarting:
		return true
	default:
		return false
	}
}

func (s *Service) updateJob(fn func(j *UpdateJobState)) {
	s.mu.Lock()
	now := time.Now().UTC()
	fn(&s.job)
	s.job.UpdatedAt = &now
	s.mu.Unlock()
}

func (s *Service) failJob(clientIP, targetTag string, err error) {
	msg := err.Error()
	s.updateJob(func(j *UpdateJobState) {
		j.Stage = StageFailed
		j.Error = msg
		j.Message = "自动更新失败：" + msg
	})
	if s.cfg.Store != nil {
		s.cfg.Store.RecordAuditAsync("system.update_failed", targetTag, msg, clientIP, false)
	}
}

func (s *Service) executeUpdatePipeline(rel *ReleaseInfo, caps Capabilities, clientIP string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	settings := s.currentSettings()
	candidates := ResolveCandidateMirrors(settings, s.cfg.BuiltinMirrors)

	// Stage 1: Probe mirrors to guarantee fastest healthy route for download.
	s.updateJob(func(j *UpdateJobState) {
		j.Stage = StageProbing
		j.Message = "正在测速 GitHub 官方与国内加速镜像，自动择优..."
	})
	probeResults := ProbeMirrors(ctx, s.cfg.HTTPClient, s.cfg.GitHubBaseURL, s.cfg.RepoSlug, candidates)
	orderedMirrors := orderNodesByProbe(candidates, probeResults)

	s.mu.Lock()
	if len(probeResults) > 0 {
		s.mirrors = probeResults
	}
	s.mu.Unlock()

	if len(orderedMirrors) == 0 {
		s.failJob(clientIP, rel.TagName, errors.New("没有可用的下载线路"))
		return
	}

	// Stage 2: Mandatory SHA256SUMS.txt fetch & trust verification BEFORE or alongside download.
	s.updateJob(func(j *UpdateJobState) {
		j.Stage = StageVerifying
		j.Message = "正在获取并验证 SHA256SUMS.txt 完整性清单..."
	})
	checksumInfo, err := FetchVerifiedChecksum(
		ctx,
		s.cfg.HTTPClient,
		s.cfg.GitHubBaseURL,
		s.cfg.RepoSlug,
		rel.TagName,
		caps.AssetName,
		settings.MirrorMode,
		orderedMirrors,
	)
	if err != nil {
		s.failJob(clientIP, rel.TagName, err)
		return
	}

	s.updateJob(func(j *UpdateJobState) {
		j.ExpectedSHA256 = checksumInfo.SHA256
		j.ChecksumSource = checksumInfo.TrustSource
	})

	// Stage 3: Stream-download target binary with automatic mirror failover.
	canonicalAssetURL := findAssetDownloadURL(rel, s.cfg.GitHubBaseURL, s.cfg.RepoSlug, caps.AssetName)
	if canonicalAssetURL == "" {
		s.failJob(clientIP, rel.TagName, fmt.Errorf("未在 Release %s 中找到目标产物 %s", rel.TagName, caps.AssetName))
		return
	}

	exeDir := filepath.Dir(caps.ExecutablePath)
	stagedFile, err := os.CreateTemp(exeDir, ".sns-update-stage-*")
	if err != nil {
		s.failJob(clientIP, rel.TagName, fmt.Errorf("无法在程序目录创建临时文件: %w", err))
		return
	}
	stagedPath := stagedFile.Name()
	_ = stagedFile.Close()
	cleanupStaged := true
	defer func() {
		if cleanupStaged {
			_ = os.Remove(stagedPath)
		}
	}()

	var downloadedHash string
	var usedMirror MirrorNode
	var dlErrs []string

	for _, mirror := range orderedMirrors {
		downloadURL := BuildMirroredURL(mirror, canonicalAssetURL)
		s.updateJob(func(j *UpdateJobState) {
			j.Stage = StageDownloading
			j.MirrorID = mirror.ID
			j.MirrorName = mirror.Name
			j.DownloadedBytes = 0
			j.TotalBytes = 0
			j.SpeedBps = 0
			j.ProgressPercent = 0
			j.Message = fmt.Sprintf("正在通过「%s」下载 %s ...", mirror.Name, caps.AssetName)
		})

		gotHash, _, dlErr := downloadAndHashAsset(ctx, s.cfg.DownloadClient, downloadURL, stagedPath, func(downloaded, total, speed int64) {
			pct := 0.0
			if total > 0 {
				pct = (float64(downloaded) / float64(total)) * 100
				if pct > 100 {
					pct = 100
				}
			}
			s.updateJob(func(j *UpdateJobState) {
				j.DownloadedBytes = downloaded
				j.TotalBytes = total
				j.SpeedBps = speed
				j.ProgressPercent = pct
			})
		})
		if dlErr != nil {
			dlErrs = append(dlErrs, fmt.Sprintf("%s: %s", mirror.Name, summarizeNetErr(dlErr)))
			continue
		}
		if !strings.EqualFold(gotHash, checksumInfo.SHA256) {
			dlErrs = append(dlErrs, fmt.Sprintf("%s: SHA-256 摘要不匹配 (got=%s)", mirror.Name, gotHash[:12]))
			continue
		}
		downloadedHash = gotHash
		usedMirror = mirror
		break
	}

	if downloadedHash == "" {
		s.failJob(clientIP, rel.TagName, fmt.Errorf("所有线路均未能通过完整下载与 SHA-256 校验: %s", strings.Join(dlErrs, " | ")))
		return
	}

	s.mu.Lock()
	s.activeMirror = findProbeOrSynthesize(usedMirror, probeResults)
	s.mu.Unlock()

	// Stage 4: Pre-swap executable header & `--version` self-check.
	s.updateJob(func(j *UpdateJobState) {
		j.Stage = StageSelfChecking
		j.ProgressPercent = 100
		j.Message = fmt.Sprintf("SHA-256 校验通过（%s），正在执行新版本可执行自检...", checksumSourceLabel(checksumInfo.TrustSource))
	})
	if err := s.cfg.SelfCheckFunc(ctx, stagedPath, rel.TagName); err != nil {
		s.failJob(clientIP, rel.TagName, err)
		return
	}

	// Stage 5: Backup current executable and atomically replace / schedule swap.
	s.updateJob(func(j *UpdateJobState) {
		j.Stage = StageReplacing
		j.Message = "自检通过，正在备份旧版本并替换程序..."
	})
	backupPath, err := s.cfg.ReplaceFunc(caps.ExecutablePath, stagedPath)
	if err != nil {
		s.failJob(clientIP, rel.TagName, err)
		return
	}
	cleanupStaged = false

	// Stage 6: Mark restarting so UI begins polling /api/health, flush state, and trigger graceful restart.
	s.updateJob(func(j *UpdateJobState) {
		j.Stage = StageRestarting
		j.Message = fmt.Sprintf("程序已更新至 %s，正在刷盘运行态并优雅重启服务...", rel.TagName)
	})
	if s.cfg.Store != nil {
		s.cfg.Store.RecordAudit(
			"system.update_applied",
			rel.TagName,
			fmt.Sprintf("已通过「%s」完成校验与替换（SHA256=%s...，校验来源=%s），准备优雅重启", usedMirror.Name, checksumInfo.SHA256[:12], checksumInfo.TrustSource),
			clientIP,
			true,
		)
	}

	// Give the frontend polling loop a short window to observe `restarting` before shutting down HTTP.
	time.Sleep(500 * time.Millisecond)

	if s.cfg.OnRestart != nil {
		if err := s.cfg.OnRestart(caps.ExecutablePath, backupPath); err != nil {
			_ = RestoreBinaryBackup(caps.ExecutablePath, backupPath)
			s.failJob(clientIP, rel.TagName, fmt.Errorf("触发优雅重启失败，已自动回滚旧版本: %w", err))
			return
		}
	} else {
		s.updateJob(func(j *UpdateJobState) {
			j.Stage = StageCompleted
			j.Message = fmt.Sprintf("已完成更新至 %s，请重启服务生效", rel.TagName)
		})
	}
}

func checksumSourceLabel(src string) string {
	switch src {
	case "official_github":
		return "GitHub 官方校验清单"
	case "cross_verified_mirrors":
		return "多镜像交叉校验一致"
	case "custom_mirror":
		return "自定义镜像校验清单"
	default:
		return src
	}
}

func mirrorsStaleOrChanged(cached []MirrorProbeResult, candidates []MirrorNode) bool {
	if len(cached) != len(candidates) {
		return true
	}
	now := time.Now().UTC()
	candSet := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		candSet[strings.ToLower(strings.TrimRight(c.Prefix, "/"))] = struct{}{}
	}
	for _, r := range cached {
		if now.Sub(r.CheckedAt) > 15*time.Minute {
			return true
		}
		key := strings.ToLower(strings.TrimRight(r.Prefix, "/"))
		if _, ok := candSet[key]; !ok {
			return true
		}
	}
	return false
}

func orderNodesByProbe(candidates []MirrorNode, probes []MirrorProbeResult) []MirrorNode {
	if len(probes) == 0 {
		return candidates
	}
	byKey := make(map[string]MirrorNode, len(candidates))
	for _, c := range candidates {
		byKey[strings.ToLower(strings.TrimRight(c.Prefix, "/"))] = c
	}

	var out []MirrorNode
	used := make(map[string]struct{}, len(candidates))
	for _, p := range probes {
		key := strings.ToLower(strings.TrimRight(p.Prefix, "/"))
		if node, ok := byKey[key]; ok {
			out = append(out, node)
			used[key] = struct{}{}
		}
	}
	for _, c := range candidates {
		key := strings.ToLower(strings.TrimRight(c.Prefix, "/"))
		if _, ok := used[key]; !ok {
			out = append(out, c)
		}
	}
	return out
}

func findProbeOrSynthesize(node MirrorNode, probes []MirrorProbeResult) *MirrorProbeResult {
	key := strings.ToLower(strings.TrimRight(node.Prefix, "/"))
	for i := range probes {
		if strings.ToLower(strings.TrimRight(probes[i].Prefix, "/")) == key {
			cp := probes[i]
			cp.Reachable = true
			return &cp
		}
	}
	return &MirrorProbeResult{
		ID:        node.ID,
		Name:      node.Name,
		Prefix:    node.Prefix,
		Region:    node.Region,
		IsCustom:  node.IsCustom,
		Reachable: true,
		CheckedAt: time.Now().UTC(),
	}
}
