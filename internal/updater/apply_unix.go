//go:build !windows

package updater

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// StageAndReplaceBinary backs up the current binary to <exe>.bak and atomically renames stagedPath over exePath.
func StageAndReplaceBinary(exePath, stagedPath string) (backupPath string, err error) {
	backupPath = exePath + ".bak"
	mode := os.FileMode(0o755)
	if st, statErr := os.Stat(exePath); statErr == nil {
		mode = st.Mode().Perm() | 0o111
	}

	// Copy current executable to backupPath (keep original inode intact until atomic rename).
	if err := copyFileAtomic(exePath, backupPath, mode); err != nil {
		return "", fmt.Errorf("备份当前程序失败: %w", err)
	}

	if err := os.Chmod(stagedPath, mode); err != nil {
		return backupPath, fmt.Errorf("设置新二进制权限失败: %w", err)
	}

	if err := os.Rename(stagedPath, exePath); err != nil {
		return backupPath, fmt.Errorf("原子替换可执行文件失败: %w", err)
	}

	return backupPath, nil
}

// RestoreBinaryBackup restores backupPath back to exePath if restart fails.
func RestoreBinaryBackup(exePath, backupPath string) error {
	if backupPath == "" {
		return nil
	}
	if _, err := os.Stat(backupPath); err != nil {
		return err
	}
	return os.Rename(backupPath, exePath)
}

// ReexecCurrentProcess replaces the running Unix process image in-place with exePath.
// Caller must flush stores and close the HTTP listener before invoking this.
func ReexecCurrentProcess(exePath string, args []string, env []string) error {
	if len(args) == 0 {
		args = []string{exePath}
	}
	return syscall.Exec(exePath, args, env)
}

func copyFileAtomic(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}
