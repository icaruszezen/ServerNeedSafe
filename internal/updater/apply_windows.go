//go:build windows

package updater

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// StageAndReplaceBinary stages the verified new binary at <exe>.new and launches a detached
// self-deleting Windows helper script that waits for the current PID to exit, swaps the binaries
// with automatic rollback on failure, and starts the updated executable.
func StageAndReplaceBinary(exePath, stagedPath string) (backupPath string, err error) {
	newPath := exePath + ".new"
	backupPath = exePath + ".old"

	_ = os.Remove(newPath)
	if err := os.Rename(stagedPath, newPath); err != nil {
		return "", fmt.Errorf("暂存新版本文件失败: %w", err)
	}

	scriptFile, err := os.CreateTemp("", "sns-self-update-*.cmd")
	if err != nil {
		return "", fmt.Errorf("创建 Windows 更新过渡脚本失败: %w", err)
	}
	scriptPath := scriptFile.Name()

	pid := os.Getpid()
	// Escape percent signs for cmd.exe safety.
	esc := func(s string) string { return strings.ReplaceAll(s, "%", "%%") }

	script := fmt.Sprintf(`@echo off
chcp 65001 >nul
setlocal enableextensions
set "PID=%d"
set "TARGET=%s"
set "NEWBIN=%s"
set "OLDBIN=%s"

rem Wait up to 25 seconds for the old ServerNeedSafe process to exit and release its mutex/file handle
set /a TRIES=0
:wait_loop
tasklist /FI "PID eq %%PID%%" 2>nul | find "%%PID%%" >nul
if errorlevel 1 goto do_swap
set /a TRIES+=1
if %%TRIES%% GEQ 25 goto do_swap
ping -n 2 127.0.0.1 >nul
goto wait_loop

:do_swap
if exist "%%OLDBIN%%" del /f /q "%%OLDBIN%%" >nul 2>&1
move /y "%%TARGET%%" "%%OLDBIN%%" >nul 2>&1
if errorlevel 1 (
  ping -n 2 127.0.0.1 >nul
  move /y "%%TARGET%%" "%%OLDBIN%%" >nul 2>&1
)
move /y "%%NEWBIN%%" "%%TARGET%%" >nul 2>&1
if errorlevel 1 (
  if exist "%%OLDBIN%%" move /y "%%OLDBIN%%" "%%TARGET%%" >nul 2>&1
  start "" "%%TARGET%%"
  goto cleanup
)

start "" "%%TARGET%%"
if errorlevel 1 (
  del /f /q "%%TARGET%%" >nul 2>&1
  if exist "%%OLDBIN%%" move /y "%%OLDBIN%%" "%%TARGET%%" >nul 2>&1
  start "" "%%TARGET%%"
)

:cleanup
(goto) 2>nul & del /f /q "%%~f0"
`, pid, esc(exePath), esc(newPath), esc(backupPath))

	if _, err := scriptFile.WriteString(script); err != nil {
		_ = scriptFile.Close()
		_ = os.Remove(scriptPath)
		return "", fmt.Errorf("写入 Windows 更新过渡脚本失败: %w", err)
	}
	if err := scriptFile.Close(); err != nil {
		_ = os.Remove(scriptPath)
		return "", err
	}

	cmd := exec.Command("cmd.exe", "/C", scriptPath)
	cmd.Dir = filepath.Dir(exePath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x00000008 | 0x00000200, // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
	}
	if err := cmd.Start(); err != nil {
		_ = os.Remove(scriptPath)
		return "", fmt.Errorf("启动 Windows 更新过渡进程失败: %w", err)
	}

	return backupPath, nil
}

// RestoreBinaryBackup is handled inside the Windows transition helper script; kept for API parity.
func RestoreBinaryBackup(exePath, backupPath string) error {
	if backupPath == "" {
		return nil
	}
	if _, err := os.Stat(backupPath); err != nil {
		return err
	}
	return os.Rename(backupPath, exePath)
}

// ReexecCurrentProcess is unused on Windows because the transition helper launches the swapped .exe
// once the current process shuts down cleanly and closes its singleton mutex.
func ReexecCurrentProcess(exePath string, args []string, env []string) error {
	return nil
}
