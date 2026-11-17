package sshmanager

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
)

const maxTextEditBytes = 2 * 1024 * 1024 // 2 MiB inline editor limit

// SFTPFileEntry describes a single remote file or directory over SFTP.
type SFTPFileEntry struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	Mode       string    `json:"mode"`
	OctalPerm  string    `json:"octal_perm"`
	ModTime    time.Time `json:"mod_time"`
	IsDir      bool      `json:"is_dir"`
	IsSymlink  bool      `json:"is_symlink"`
}

// SFTPListResponse returns normalized remote directory path and entries.
type SFTPListResponse struct {
	CurrentPath string          `json:"current_path"`
	HomePath    string          `json:"home_path"`
	Entries     []SFTPFileEntry `json:"entries"`
}

func (m *Manager) withSFTP(serverID, clientIP string, fn func(sc *sftp.Client, srvName string) error) error {
	sshClient, err := m.Dial(serverID, DialOptions{ClientIP: clientIP})
	if err != nil {
		return err
	}
	defer sshClient.Close()

	sc, err := sftp.NewClient(sshClient.Client)
	if err != nil {
		return fmt.Errorf("初始化 SFTP 子系统失败: %w", err)
	}
	defer sc.Close()

	return fn(sc, sshClient.Server.Name)
}

func resolveSFTPDir(sc *sftp.Client, requested string, defaultPath string) (cwd string, home string, err error) {
	home, err = sc.Getwd()
	if err != nil || home == "" {
		home = "/"
	}
	target := strings.TrimSpace(requested)
	if target == "" {
		if strings.TrimSpace(defaultPath) != "" {
			target = strings.TrimSpace(defaultPath)
		} else {
			target = home
		}
	}
	if target == "~" {
		target = home
	} else if strings.HasPrefix(target, "~/") {
		target = path.Join(home, strings.TrimPrefix(target, "~/"))
	}
	if !strings.HasPrefix(target, "/") {
		target = path.Join(home, target)
	}
	realTarget, err := sc.RealPath(target)
	if err != nil {
		realTarget = path.Clean(target)
	}
	return realTarget, home, nil
}

// SFTPList lists remote files and directories at targetDir.
func (m *Manager) SFTPList(serverID, targetDir, clientIP string) (*SFTPListResponse, error) {
	var resp *SFTPListResponse
	srv, err := m.store.GetServerSecret(serverID)
	if err != nil {
		return nil, err
	}

	err = m.withSFTP(serverID, clientIP, func(sc *sftp.Client, _ string) error {
		resolved, home, err := resolveSFTPDir(sc, targetDir, srv.DefaultPath)
		if err != nil {
			return err
		}
		infos, err := sc.ReadDir(resolved)
		if err != nil {
			return fmt.Errorf("读取目录 %s 失败: %w", resolved, err)
		}

		entries := make([]SFTPFileEntry, 0, len(infos))
		for _, info := range infos {
			name := info.Name()
			if name == "." || name == ".." {
				continue
			}
			fullPath := path.Join(resolved, name)
			isLink := info.Mode()&os.ModeSymlink != 0
			isDir := info.IsDir()
			size := info.Size()

			// If symlink, inspect target to check if it points to a directory
			if isLink {
				if targetStat, statErr := sc.Stat(fullPath); statErr == nil {
					isDir = targetStat.IsDir()
					size = targetStat.Size()
				}
			}

			entries = append(entries, SFTPFileEntry{
				Name:      name,
				Path:      fullPath,
				Size:      size,
				Mode:      info.Mode().String(),
				OctalPerm: fmt.Sprintf("%04o", info.Mode().Perm()),
				ModTime:   info.ModTime().UTC(),
				IsDir:     isDir,
				IsSymlink: isLink,
			})
		}

		slices.SortFunc(entries, func(a, b SFTPFileEntry) int {
			if a.IsDir != b.IsDir {
				if a.IsDir {
					return -1
				}
				return 1
			}
			return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
		})

		resp = &SFTPListResponse{
			CurrentPath: resolved,
			HomePath:    home,
			Entries:     entries,
		}
		return nil
	})
	return resp, err
}

// SFTPReadText reads a UTF-8/text configuration or log file up to 2 MiB for online editing.
func (m *Manager) SFTPReadText(serverID, remotePath, clientIP string) (string, error) {
	var content string
	err := m.withSFTP(serverID, clientIP, func(sc *sftp.Client, _ string) error {
		stat, err := sc.Stat(remotePath)
		if err != nil {
			return fmt.Errorf("读取文件信息失败: %w", err)
		}
		if stat.IsDir() {
			return errors.New("无法以文本方式打开目录")
		}
		if stat.Size() > maxTextEditBytes {
			return fmt.Errorf("文件大小 (%d KB) 超过在线编辑限制 (2 MB)，请下载后编辑", stat.Size()/1024)
		}
		f, err := sc.Open(remotePath)
		if err != nil {
			return fmt.Errorf("打开远程文件失败: %w", err)
		}
		defer f.Close()

		data, err := io.ReadAll(io.LimitReader(f, maxTextEditBytes+1))
		if err != nil {
			return err
		}
		// Simple binary file detection on first 4KB
		sample := data
		if len(sample) > 4096 {
			sample = sample[:4096]
		}
		if bytes.IndexByte(sample, 0) >= 0 {
			return errors.New("检测到二进制文件格式，不支持在线文本编辑，请使用下载功能")
		}
		content = string(data)
		return nil
	})
	return content, err
}

// SFTPWriteText writes text content to a remote file over SFTP.
func (m *Manager) SFTPWriteText(serverID, remotePath, content, clientIP string) error {
	return m.withSFTP(serverID, clientIP, func(sc *sftp.Client, srvName string) error {
		f, err := sc.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if err != nil {
			return fmt.Errorf("写入远程文件失败: %w", err)
		}
		defer f.Close()

		if _, err := io.WriteString(f, content); err != nil {
			return err
		}
		m.store.RecordAudit("sftp.write", fmt.Sprintf("%s:%s", srvName, remotePath), "在线编辑保存远程文件", clientIP, true)
		return nil
	})
}

// SFTPUpload streams an uploaded file into targetDir/fileName over SFTP.
func (m *Manager) SFTPUpload(serverID, targetDir, fileName string, src io.Reader, clientIP string) (string, int64, error) {
	cleanName := path.Base(strings.ReplaceAll(fileName, "\\", "/"))
	if cleanName == "" || cleanName == "." || cleanName == "/" {
		return "", 0, errors.New("上传文件名无效")
	}
	var destPath string
	var written int64

	err := m.withSFTP(serverID, clientIP, func(sc *sftp.Client, srvName string) error {
		resolvedDir, _, err := resolveSFTPDir(sc, targetDir, "")
		if err != nil {
			return err
		}
		destPath = path.Join(resolvedDir, cleanName)
		dst, err := sc.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if err != nil {
			return fmt.Errorf("创建远程文件 %s 失败: %w", destPath, err)
		}
		defer dst.Close()

		n, err := io.Copy(dst, src)
		if err != nil {
			return fmt.Errorf("传输文件数据失败: %w", err)
		}
		written = n
		m.store.RecordAudit("sftp.upload", fmt.Sprintf("%s:%s", srvName, destPath), fmt.Sprintf("上传文件 (%d bytes)", written), clientIP, true)
		return nil
	})
	return destPath, written, err
}

// SFTPDownloadStream opens a remote file and returns a reader, file info, and cleanup function.
func (m *Manager) SFTPDownloadStream(serverID, remotePath, clientIP string) (io.ReadCloser, os.FileInfo, func(), error) {
	sshClient, err := m.Dial(serverID, DialOptions{ClientIP: clientIP})
	if err != nil {
		return nil, nil, nil, err
	}
	sc, err := sftp.NewClient(sshClient.Client)
	if err != nil {
		_ = sshClient.Close()
		return nil, nil, nil, fmt.Errorf("初始化 SFTP 失败: %w", err)
	}
	stat, err := sc.Stat(remotePath)
	if err != nil {
		_ = sc.Close()
		_ = sshClient.Close()
		return nil, nil, nil, fmt.Errorf("获取远程文件失败: %w", err)
	}
	if stat.IsDir() {
		_ = sc.Close()
		_ = sshClient.Close()
		return nil, nil, nil, errors.New("暂不支持直接流式下载整个目录，请选择具体文件")
	}
	f, err := sc.Open(remotePath)
	if err != nil {
		_ = sc.Close()
		_ = sshClient.Close()
		return nil, nil, nil, fmt.Errorf("打开远程文件失败: %w", err)
	}

	m.store.RecordAudit("sftp.download", fmt.Sprintf("%s:%s", sshClient.Server.Name, remotePath), fmt.Sprintf("下载文件 (%d bytes)", stat.Size()), clientIP, true)

	cleanup := func() {
		_ = f.Close()
		_ = sc.Close()
		_ = sshClient.Close()
	}
	return f, stat, cleanup, nil
}

// SFTPDownloadBytes downloads a remote file directly into client memory (up to maxBytes) for browser Blob saving.
func (m *Manager) SFTPDownloadBytes(serverID, remotePath string, maxBytes int64, clientIP string) ([]byte, string, error) {
	if maxBytes <= 0 {
		maxBytes = 128 * 1024 * 1024 // 128 MiB default client WASM cap
	}
	rc, stat, cleanup, err := m.SFTPDownloadStream(serverID, remotePath, clientIP)
	if err != nil {
		return nil, "", err
	}
	defer cleanup()

	if stat.Size() > maxBytes {
		return nil, "", fmt.Errorf("文件大小 (%d MB) 超过浏览器端内存下载上限 (%d MB)", stat.Size()/(1024*1024), maxBytes/(1024*1024))
	}
	data, err := io.ReadAll(io.LimitReader(rc, maxBytes+1))
	if err != nil {
		return nil, "", err
	}
	return data, stat.Name(), nil
}

// SFTPMkdir creates a directory (including parents) over SFTP.
func (m *Manager) SFTPMkdir(serverID, remotePath, clientIP string) error {
	return m.withSFTP(serverID, clientIP, func(sc *sftp.Client, srvName string) error {
		if err := sc.MkdirAll(remotePath); err != nil {
			return fmt.Errorf("创建目录失败: %w", err)
		}
		m.store.RecordAudit("sftp.mkdir", fmt.Sprintf("%s:%s", srvName, remotePath), "创建远程目录", clientIP, true)
		return nil
	})
}

// SFTPRename renames or moves a remote file/directory.
func (m *Manager) SFTPRename(serverID, oldPath, newPath, clientIP string) error {
	return m.withSFTP(serverID, clientIP, func(sc *sftp.Client, srvName string) error {
		if err := sc.PosixRename(oldPath, newPath); err != nil {
			if fallbackErr := sc.Rename(oldPath, newPath); fallbackErr != nil {
				return fmt.Errorf("重命名失败: %w", fallbackErr)
			}
		}
		m.store.RecordAudit("sftp.rename", fmt.Sprintf("%s:%s -> %s", srvName, oldPath, newPath), "重命名远程文件/目录", clientIP, true)
		return nil
	})
}

// SFTPRemove removes a remote file or directory (recursively if directory).
func (m *Manager) SFTPRemove(serverID, remotePath, clientIP string) error {
	clean := path.Clean(remotePath)
	if clean == "/" || clean == "." || clean == "" {
		return errors.New("安全保护：禁止删除根目录")
	}
	return m.withSFTP(serverID, clientIP, func(sc *sftp.Client, srvName string) error {
		if err := removeRecursive(sc, clean); err != nil {
			return err
		}
		m.store.RecordAudit("sftp.delete", fmt.Sprintf("%s:%s", srvName, clean), "删除远程文件/目录", clientIP, true)
		return nil
	})
}

func removeRecursive(sc *sftp.Client, target string) error {
	stat, err := sc.Lstat(target)
	if err != nil {
		return fmt.Errorf("访问路径 %s 失败: %w", target, err)
	}
	if !stat.IsDir() || (stat.Mode()&os.ModeSymlink != 0) {
		return sc.Remove(target)
	}
	entries, err := sc.ReadDir(target)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == "." || entry.Name() == ".." {
			continue
		}
		if err := removeRecursive(sc, path.Join(target, entry.Name())); err != nil {
			return err
		}
	}
	return sc.RemoveDirectory(target)
}

// SFTPChmod updates POSIX octal permissions (e.g. "0600", "755") on a remote path.
func (m *Manager) SFTPChmod(serverID, remotePath, octalPerm, clientIP string) error {
	parsed, err := strconv.ParseUint(strings.TrimSpace(octalPerm), 8, 32)
	if err != nil || parsed > 0o7777 {
		return errors.New("无效的八进制权限值（示例：0644 或 0755）")
	}
	return m.withSFTP(serverID, clientIP, func(sc *sftp.Client, srvName string) error {
		if err := sc.Chmod(remotePath, os.FileMode(parsed)); err != nil {
			return fmt.Errorf("修改权限失败: %w", err)
		}
		m.store.RecordAudit("sftp.chmod", fmt.Sprintf("%s:%s", srvName, remotePath), fmt.Sprintf("修改权限为 %04o", parsed), clientIP, true)
		return nil
	})
}
