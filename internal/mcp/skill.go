package mcp

import "fmt"

// StandardPatrolSkillMarkdown generates an out-of-the-box SKILL.md operational guide that users can
// drop directly into Claude Code, Codex, Antigravity, or Cursor so the local AI follows ServerNeedSafe's
// exact SRE inspection, forensic drill-down, memory evolution, and HITL approval workflow.
func StandardPatrolSkillMarkdown(endpointURL string) string {
	if endpointURL == "" {
		endpointURL = "http://127.0.0.1:18899/api/mcp"
	}
	return fmt.Sprintf(`---
name: serverneedsafe-ai-patrol
description: 使用 ServerNeedSafe MCP 网关接管多服务器安全巡检、只读 SSH/SFTP 深度取证、主机画像与记忆沉淀及 HITL 受控修复提案。
---

# ServerNeedSafe 外部 AI 巡检与安全运维 SOP

本技能配合 ServerNeedSafe 内置 MCP 网关（默认端点：`+"`%s`"+`）使用。所有受管主机的 SSH 密码与私钥均由 ServerNeedSafe 物理隔离，本地 AI 绝不接触凭据原文。

## 一、接管后台定时巡检队列（推荐日常工作流）

1. **检查待研判任务**：调用 `+"`list_patrol_records(pending_only=true)`"+` 查看后台 7×24 巡检发现的异常记录。
2. **认领任务与加载上下文**：对目标异常记录调用 `+"`claim_patrol(patrol_record_id)`"+`，系统会返回巡检指标、全局 `+"`AGENTS.md`"+` 规范、受检主机环境画像（端口用途、避坑红线）及长期记忆。
3. **只读深度钻取取证**：不要停留在表层阈值告警，优先用只读工具核实真实根因（注意按主机 OS 区分 Linux 与 macOS/Darwin 命令）：
   - 进程与负载：`+"`exec_readonly_ssh`"+` 执行 Linux `+"`ps aux --sort=-%%cpu | head -n 15`"+`、`+"`free -h`"+`、`+"`uptime`"+`；或 macOS `+"`ps -axr -o pid,user,pcpu,pmem,rss,comm | head -n 15`"+`、`+"`vm_stat`"+`、`+"`sysctl -n vm.loadavg`"+`
   - 端口与网络：`+"`exec_readonly_ssh`"+` 执行 Linux `+"`ss -tulnp`"+` 或 macOS `+"`netstat -anv -p tcp`"+` / `+"`lsof -nP -iTCP -sTCP:LISTEN`"+`（对比主机画像已知业务端口，避免误报）
   - 磁盘与日志：`+"`exec_readonly_ssh`"+` 执行 Linux `+"`df -hT`"+`、`+"`journalctl -n 60 --no-pager`"+`；或 macOS `+"`df -h`"+`、`+"`launchctl list`"+`、`+"`log show --last 1h`"+`
   - 关键配置核查：`+"`sftp_read_file`"+` 查看 Nginx / SSH / Systemd 配置
4. **回写结构化巡检报告**：调用 `+"`submit_patrol_report`"+` 提交：
   - `+"`summary`"+`：一句话核心结论（80 字以内）
   - `+"`root_cause`"+`：结合指标与取证证据的完整根因分析
   - `+"`deep_evidence`"+`：关键命令行或日志线索摘要（严禁含密码/Token）
   - `+"`recommendations`"+`：按优先级排序的处置与加固建议
   - 填写 `+"`client_name`"+`（如 Claude Code / Codex / Antigravity / Cursor）与 `+"`model_name`"+`，按需开启 `+"`dispatch_webhook: true`"+` 推送至飞书/钉钉/企微群。

## 二、主动发起全量体检

当用户要求“巡检一下我的服务器”时：
1. 调用 `+"`get_ops_context`"+` + `+"`get_monitor_overview`"+` 掌握基线。
2. 调用 `+"`run_patrol`"+` 发起实时只读扫描并获得 `+"`patrol_record_id`"+`。
3. 对异常主机做只读钻取后调用 `+"`submit_patrol_report`"+` 归档报告。

## 三、知识沉淀与受控修复 (HITL)

- **主机画像更新**：发现新的服务、部署目录或端口业务用途时，调用 `+"`update_host_memory`"+`。
- **长期记忆沉淀**：定位典型故障根因或重要变更结论后，调用 `+"`save_memory`"+`。
- **受控修复提案**：若令牌具备 `+"`ops_propose`"+` 权限且确实需要清理日志、重载服务或修改配置文件：
  1. 严禁直接尝试在 `+"`exec_readonly_ssh`"+` 中执行变更命令。
  2. 调用 `+"`propose_ssh_command`"+` 或 `+"`propose_sftp_write`"+`（附带 `+"`patrol_record_id`"+` 与清晰变更理由/回滚说明），系统会自动生成 Unified Diff 落入 ServerNeedSafe Web 端审批队列。
  3. 告知管理员前往控制台「AI 智能运维 → 外部 AI 接管 (MCP)」批准后，调用 `+"`get_approval_status(approval_id)`"+` 获取执行回显并二次验证服务健康状态。
`, endpointURL)
}
