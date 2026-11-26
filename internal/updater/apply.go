package updater

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/icaruszezen/ServerNeedSafe/internal/version"
)

// Capabilities describes what update actions the current runtime environment supports.
type Capabilities struct {
	DeployMode         string `json:"deploy_mode"` // "desktop" or "server"
	InDocker           bool   `json:"in_docker"`
	CanSelfUpdate      bool   `json:"can_self_update"`
	CannotUpdateReason string `json:"cannot_update_reason,omitempty"`
	ExecutablePath     string `json:"executable_path,omitempty"`
	AssetName          string `json:"asset_name,omitempty"`
	GOOS               string `json:"goos"`
	GOARCH             string `json:"goarch"`
}

// DockerMirrorCommand provides a ready-to-copy China-accelerated GHCR pull & restart command.
type DockerMirrorCommand struct {
	Name    string `json:"name"`
	Image   string `json:"image"`
	Command string `json:"command"`
}

// DockerUpgradeCommands provides guided upgrade commands for Docker deployments.
type DockerUpgradeCommands struct {
	Tag            string                `json:"tag"`
	OfficialImage  string                `json:"official_image"`
	OfficialPull   string                `json:"official_pull"`
	ComposeUpgrade string                `json:"compose_upgrade"`
	ChinaMirrors   []DockerMirrorCommand `json:"china_mirrors"`
}

// DetectInDocker checks standard container indicators (`SNS_IN_DOCKER=1`, `/.dockerenv`, cgroups).
func DetectInDocker() bool {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("SNS_IN_DOCKER")), "1") ||
		strings.EqualFold(strings.TrimSpace(os.Getenv("SNS_IN_DOCKER")), "true") {
		return true
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := strings.ToLower(string(data))
		if strings.Contains(s, "docker") || strings.Contains(s, "containerd") || strings.Contains(s, "kubepods") {
			return true
		}
	}
	return false
}

// ExpectedAssetName returns the deterministic GitHub Release asset name matching CI build-release.yml.
func ExpectedAssetName(deployMode, goos, goarch string) string {
	switch goos {
	case "windows":
		if goarch == "amd64" || goarch == "arm64" {
			return fmt.Sprintf("ServerNeedSafe-windows-%s.exe", goarch)
		}
	case "linux":
		if deployMode == "server" && (goarch == "amd64" || goarch == "arm64") {
			return fmt.Sprintf("sns-server-linux-%s", goarch)
		}
	}
	return ""
}

// BuildDockerUpgradeCommands builds official and China-accelerated GHCR upgrade commands for a tag.
func BuildDockerUpgradeCommands(tag string) *DockerUpgradeCommands {
	t := strings.TrimSpace(tag)
	if t == "" {
		t = "latest"
	}
	// Docker tags published by docker/metadata-action use semver without leading "v" (e.g. 2.4.0) plus "latest".
	imageTag := strings.TrimPrefix(t, "v")
	if imageTag == "" {
		imageTag = "latest"
	}
	officialImg := fmt.Sprintf("%s:%s", version.GHCRImage, imageTag)
	officialLatest := fmt.Sprintf("%s:latest", version.GHCRImage)

	njuImg := fmt.Sprintf("ghcr.nju.edu.cn/icaruszezen/serverneedsafe:%s", imageTag)
	daocloudImg := fmt.Sprintf("ghcr.m.daocloud.io/icaruszezen/serverneedsafe:%s", imageTag)

	return &DockerUpgradeCommands{
		Tag:           t,
		OfficialImage: officialImg,
		OfficialPull: fmt.Sprintf(
			"docker pull %s && docker tag %s %s && docker compose up -d --force-recreate",
			officialImg, officialImg, officialLatest,
		),
		ComposeUpgrade: "docker compose pull && docker compose up -d",
		ChinaMirrors: []DockerMirrorCommand{
			{
				Name:  "南京大学 GHCR 镜像加速 (推荐)",
				Image: njuImg,
				Command: fmt.Sprintf(
					"docker pull %s && docker tag %s %s && docker compose up -d --force-recreate",
					njuImg, njuImg, officialLatest,
				),
			},
			{
				Name:  "DaoCloud GHCR 镜像加速",
				Image: daocloudImg,
				Command: fmt.Sprintf(
					"docker pull %s && docker tag %s %s && docker compose up -d --force-recreate",
					daocloudImg, daocloudImg, officialLatest,
				),
			},
		},
	}
}

// DetectCapabilities inspects the running environment to decide whether in-place self-update is permitted.
func DetectCapabilities(deployMode, currentVer, exePath string, inDocker bool) Capabilities {
	goos := runtime.GOOS
	goarch := runtime.GOARCH
	asset := ExpectedAssetName(deployMode, goos, goarch)

	caps := Capabilities{
		DeployMode:     deployMode,
		InDocker:       inDocker,
		ExecutablePath: exePath,
		AssetName:      asset,
		GOOS:           goos,
		GOARCH:         goarch,
	}

	if inDocker {
		caps.CanSelfUpdate = false
		caps.CannotUpdateReason = "当前运行在 Docker 非 Root 不可变容器中，请使用下方宿主机 Docker 升级命令拉取新镜像重建容器"
		return caps
	}
	if version.IsDevVersion(currentVer) {
		caps.CanSelfUpdate = false
		caps.CannotUpdateReason = "当前为本地开发构建版本 (dev)，默认禁止自动覆盖二进制文件以防误替换开发环境"
		return caps
	}
	if asset == "" {
		caps.CanSelfUpdate = false
		caps.CannotUpdateReason = fmt.Sprintf("当前运行平台 (%s/%s, mode=%s) 暂无官方预编译单文件自动更新产物", goos, goarch, deployMode)
		return caps
	}
	if strings.TrimSpace(exePath) == "" {
		caps.CanSelfUpdate = false
		caps.CannotUpdateReason = "无法解析当前可执行文件路径"
		return caps
	}
	if err := checkExecutableDirWritable(exePath); err != nil {
		caps.CanSelfUpdate = false
		caps.CannotUpdateReason = fmt.Sprintf("当前程序所在目录缺少写权限，无法原地替换二进制: %v", err)
		return caps
	}

	caps.CanSelfUpdate = true
	return caps
}

func resolveCurrentExecutable() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved
	}
	return exe
}

func checkExecutableDirWritable(exePath string) error {
	dir := filepath.Dir(exePath)
	f, err := os.CreateTemp(dir, ".sns-update-perm-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

// CleanupPreviousBackup removes leftover .old / .bak / .new staging artifacts from a previous update.
func CleanupPreviousBackup() {
	exePath := resolveCurrentExecutable()
	if exePath == "" {
		return
	}
	for _, suffix := range []string{".old", ".bak", ".new"} {
		candidate := exePath + suffix
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			_ = os.Remove(candidate)
		}
	}
}

// downloadAndHashAsset streams an asset to dstPath while computing its SHA-256 and reporting progress.
func downloadAndHashAsset(
	ctx context.Context,
	client *http.Client,
	downloadURL string,
	dstPath string,
	onProgress func(downloaded, total int64, speedBps int64),
) (string, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", updaterUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("下载返回 HTTP %d", resp.StatusCode)
	}
	// Reject obvious HTML error pages returned by broken proxies.
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "text/html") {
		return "", 0, errors.New("镜像返回了 HTML 页面而非二进制安装包")
	}

	f, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", 0, fmt.Errorf("创建临时更新文件失败: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

	hasher := sha256.New()
	total := resp.ContentLength
	var downloaded int64
	buf := make([]byte, 64*1024)
	startedAt := time.Now()
	lastReport := startedAt

	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, wErr := f.Write(buf[:n]); wErr != nil {
				return "", downloaded, fmt.Errorf("写入临时文件失败: %w", wErr)
			}
			_, _ = hasher.Write(buf[:n])
			downloaded += int64(n)

			now := time.Now()
			if onProgress != nil && (now.Sub(lastReport) >= 150*time.Millisecond || readErr == io.EOF) {
				elapsed := now.Sub(startedAt).Seconds()
				var speed int64
				if elapsed > 0.05 {
					speed = int64(float64(downloaded) / elapsed)
				}
				onProgress(downloaded, total, speed)
				lastReport = now
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", downloaded, fmt.Errorf("读取下载流中断: %w", readErr)
		}
	}

	if downloaded < 1024 {
		return "", downloaded, fmt.Errorf("下载文件体积异常过小 (%d 字节)", downloaded)
	}
	if err := f.Sync(); err != nil {
		return "", downloaded, err
	}
	if err := f.Close(); err != nil {
		return "", downloaded, err
	}
	if onProgress != nil {
		elapsed := time.Since(startedAt).Seconds()
		var speed int64
		if elapsed > 0.05 {
			speed = int64(float64(downloaded) / elapsed)
		}
		onProgress(downloaded, total, speed)
	}

	return hex.EncodeToString(hasher.Sum(nil)), downloaded, nil
}

// verifyBinaryHeader checks the ELF/PE magic signature matching targetOS.
func verifyBinaryHeader(filePath, targetOS string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return fmt.Errorf("读取可执行文件头失败: %w", err)
	}
	switch targetOS {
	case "windows":
		if hdr[0] != 'M' || hdr[1] != 'Z' {
			return errors.New("文件头校验失败：不是有效的 Windows PE 可执行文件")
		}
	case "linux":
		if !bytes.Equal(hdr, []byte{0x7f, 'E', 'L', 'F'}) {
			return errors.New("文件头校验失败：不是有效的 Linux ELF 可执行文件")
		}
	}
	return nil
}

// defaultSelfCheckBinary verifies file header and runs `<binary> --version` before swapping.
func defaultSelfCheckBinary(ctx context.Context, binaryPath, expectedTag string) error {
	if err := verifyBinaryHeader(binaryPath, runtime.GOOS); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(binaryPath, 0o755); err != nil {
			return fmt.Errorf("设置可执行权限失败: %w", err)
		}
	}

	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(checkCtx, binaryPath, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("新版本自检启动失败 (--version): %v %s", err, strings.TrimSpace(string(out)))
	}
	text := strings.TrimSpace(string(out))
	if text == "" {
		return errors.New("新版本自检未输出版本信息")
	}
	expectedClean := strings.TrimPrefix(strings.TrimSpace(expectedTag), "v")
	if !strings.Contains(text, expectedTag) && (expectedClean == "" || !strings.Contains(text, expectedClean)) {
		if !strings.Contains(text, "ServerNeedSafe") {
			return fmt.Errorf("新版本自检输出异常: %q", text)
		}
	}
	return nil
}
