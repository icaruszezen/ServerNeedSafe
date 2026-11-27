import type { MonitorAlert, ServerView } from '../types';

function severityLabelZH(severity?: string): string {
  if (severity === 'critical') return '严重 (critical)';
  if (severity === 'warning') return '警告 (warning)';
  return severity || '未知';
}

function statusLabelZH(status?: string): string {
  if (status === 'firing') return '触发中 (firing)';
  if (status === 'acknowledged') return '已知晓 (acknowledged)';
  if (status === 'resolved') return '已恢复 (resolved)';
  return status || '未知';
}

function isMacOSLabel(osText?: string): boolean {
  const low = (osText || '').toLowerCase();
  return low.includes('darwin') || low.includes('macos') || low.includes('mac os');
}

function formatInlineCode(value: string): string {
  const trimmed = value.trim();
  if (!trimmed.includes('`')) {
    return `\`${trimmed}\``;
  }
  return `\`\` ${trimmed} \`\``;
}

/**
 * Builds a copy-ready diagnosis prompt tailored for external MCP AI clients
 * (Claude Code / Codex / Antigravity / Cursor) connected to ServerNeedSafe MCP.
 *
 * Prefers the backend-generated snapshot-aware `advice.mcp_prompt` when available,
 * and falls back to generating an equivalent structured prompt directly from the
 * alert and optional ServerView metadata.
 */
export function buildAlertMCPPrompt(al: MonitorAlert, server?: ServerView): string {
  const backendPrompt = al.advice?.mcp_prompt?.trim();
  if (backendPrompt) {
    return backendPrompt;
  }

  const lines: string[] = [];
  const isResolved = al.status === 'resolved';
  const serverName = (al.server_name || server?.name || al.server_id || '未知主机').trim();
  const serverID = (al.server_id || server?.id || '').trim();
  const hostText = (
    al.host ||
    (server ? `${server.host}${server.port ? `:${server.port}` : ''}` : '')
  ).trim();
  const osText = (server?.last_os_info || '').trim();
  const isMac = isMacOSLabel(osText);
  const isConnBlocked = al.rule_kind === 'offline' || al.rule_kind === 'host_key_changed';

  if (isResolved) {
    lines.push(
      '请使用已接入的 ServerNeedSafe MCP（`serverneedsafe`）协助复盘以下已恢复的服务器监控告警，确认根因与隐患是否彻底消除：'
    );
  } else {
    lines.push(
      '请使用已接入的 ServerNeedSafe MCP（`serverneedsafe`）协助对以下服务器监控告警进行深度排查与处置：'
    );
  }
  lines.push('');
  lines.push('【目标主机与告警上下文】');
  lines.push(
    serverID
      ? `- 服务器名称：${serverName}（server_id: ${formatInlineCode(serverID)}）`
      : `- 服务器名称：${serverName}`
  );
  if (hostText) {
    lines.push(`- 主机地址：${hostText}`);
  }
  if (osText) {
    lines.push(`- 系统环境：${osText}`);
  }
  if (server?.group) {
    lines.push(`- 所属分组：${server.group}`);
  }
  if (al.id) {
    lines.push(`- 告警 ID：${formatInlineCode(al.id)}`);
  }
  if (al.title) {
    lines.push(`- 告警标题：${al.title}`);
  }
  if (al.rule_name || al.rule_kind) {
    const ruleDesc =
      al.rule_name && al.rule_kind
        ? `${al.rule_name} (${formatInlineCode(al.rule_kind)})`
        : al.rule_name || formatInlineCode(al.rule_kind);
    lines.push(`- 规则类型：${ruleDesc}`);
  }

  const statusParts = [
    `严重级别：${severityLabelZH(al.severity)}`,
    `当前状态：${statusLabelZH(al.status)}`,
  ];
  if (al.occurrences > 0) {
    statusParts.push(`累计触发：${al.occurrences} 次`);
  }
  lines.push(`- ${statusParts.join(' · ')}`);

  const timeParts: string[] = [];
  if (al.triggered_at) timeParts.push(`首次触发：${al.triggered_at}`);
  if (al.last_seen_at) timeParts.push(`最近检测：${al.last_seen_at}`);
  if (isResolved && al.resolved_at) timeParts.push(`恢复时间：${al.resolved_at}`);
  if (timeParts.length > 0) {
    lines.push(`- 时间信息：${timeParts.join(' · ')}`);
  }

  if (al.metric_text) {
    lines.push(
      al.threshold_text
        ? `- 实测指标：${al.metric_text}（阈值条件：${al.threshold_text}）`
        : `- 实测指标：${al.metric_text}`
    );
  }
  if (al.detail) {
    lines.push(`- 告警详情：${al.detail}`);
  }

  const advice = al.advice;
  if (advice?.summary) {
    lines.push(`- 系统初判摘要：${advice.summary}`);
  }
  if (advice?.evidence && advice.evidence.length > 0) {
    lines.push('- 最新监控快照线索：');
    for (const ev of advice.evidence) {
      if (ev.trim()) lines.push(`  * ${ev.trim()}`);
    }
  }

  const readonlyCmds = (advice?.commands || [])
    .filter((c) => c.risk === 'readonly' && c.command.trim())
    .slice(0, 4);
  if (readonlyCmds.length > 0) {
    lines.push(
      isConnBlocked
        ? '- 带外/恢复连通后参考排查命令：'
        : '- 可优先参考的只读排查命令（通过 `exec_readonly_ssh` 执行）：'
    );
    for (const c of readonlyCmds) {
      lines.push(`  * ${c.label}：${formatInlineCode(c.command)}`);
    }
  }

  const mutatingCmds = (advice?.commands || [])
    .filter((c) => c.risk === 'mutating' && c.command.trim())
    .slice(0, 2);
  if (mutatingCmds.length > 0 && !isConnBlocked) {
    lines.push('- 参考修复操作（如经取证确认需执行，必须走 `propose_change_plan` 提交审批）：');
    for (const c of mutatingCmds) {
      lines.push(`  * ${c.label}：${formatInlineCode(c.command)}`);
    }
  }

  if (advice?.runbooks && advice.runbooks.length > 0) {
    lines.push('- 已匹配关联 Runbook（可调用 `get_runbook` 调阅完整 SOP）：');
    for (const rb of advice.runbooks) {
      lines.push(`  * ${formatInlineCode(rb.id)} — ${rb.title}`);
    }
  }

  if (advice?.quick_actions && advice.quick_actions.length > 0) {
    const labels = advice.quick_actions
      .map((qa) => qa.label.trim())
      .filter(Boolean);
    if (labels.length > 0) {
      lines.push(
        `- 面板内置快捷处置项（若取证确认属于预期变更，可提醒我在告警页一键操作）：${labels.join('、')}`
      );
    }
  }

  const sidArg = serverID ? JSON.stringify(serverID) : '"<server_id>"';
  lines.push('');
  lines.push('【MCP 排查与处置要求】');
  if (serverID) {
    lines.push(
      `1. 加载规范与态势：先调用 \`get_ops_context(server_ids=[${sidArg}])\` 与 \`get_server_detail(server_id=${sidArg}, range="1h")\`（必要时结合 \`list_alerts(server_id=${sidArg})\`、\`search_memory\` 或 \`get_runbook\`），阅读 \`AGENTS.md\` 运维规范、该主机画像（已知端口用途、部署路径与运维红线）及近期时序变化，避免误判正常业务。`
    );
  } else {
    lines.push(
      '1. 加载规范与态势：先调用 `list_servers` 确认目标主机的 `server_id`，再调用 `get_ops_context`、`get_server_detail` 与 `list_alerts` 获取 `AGENTS.md` 运维规范、主机画像与近期时序变化，避免误判正常业务。'
    );
  }

  if (al.rule_kind === 'offline') {
    lines.push(
      `2. 连通性核查：先调用 \`probe_server(server_id=${sidArg})\` 复核实时连通性与报错；若已恢复连通再通过 \`exec_readonly_ssh\` 核查宕机/sshd 日志；若仍不可达，请结合跳板链路与历史监控指标分析可能原因，并给出云控制台 / VNC 带外排查清单。`
    );
  } else if (al.rule_kind === 'host_key_changed') {
    lines.push(
      '2. 指纹核验与风险排查：切勿尝试绕过或忽略 SSH 主机指纹校验；请结合 `get_server_detail` 与长期记忆核实是否存在计划重装、迁移或换 IP 记录，并给出带外核验 `/etc/ssh/ssh_host_*_key.pub` 指纹及排查中间人风险的步骤；仅当人工核验合法后，才指引我在「安全保险库 → 已信任主机指纹」更新指纹。'
    );
  } else {
    const macNote = isMac ? '；目标主机为 macOS/Darwin，请使用 BSD/macOS 兼容命令' : '';
    lines.push(
      `2. 只读深度取证：使用 \`exec_readonly_ssh(server_ids=[${sidArg}], ...)\` 与 \`sftp_read_file\` / \`sftp_list_dir\` 深入核查进程、日志、端口或配置现场证据，锁定确凿根因（严禁在只读接口尝试变更命令，也勿尝试读取敏感凭据/私钥文件${macNote}）。`
    );
  }

  if (isResolved) {
    lines.push(
      '3. 复盘结论与受控加固 (HITL)：按「根因复盘 → 关键证据 → 残留风险评估 → 加固预防建议」输出中文报告；若确需执行线上加固或修改配置，严禁绕过审批，必须统一调用 `propose_change_plan` 提交有序变更计划（写明变更目的、影响范围与回滚方案），等待我在 ServerNeedSafe Web 端「执行审批」批准后，再通过 `wait_for_approval` / `get_approval_status` 查看回显并复测核验。'
    );
  } else {
    lines.push(
      '3. 诊断结论与受控修复 (HITL)：按「根因结论 → 关键现场证据 → 影响范围 → 处置与加固建议」输出中文报告；若确需执行线上修复命令或修改配置文件，严禁绕过审批，必须统一调用 `propose_change_plan` 提交有序变更计划（可在同一计划内混合编排 `sftp_write_file` 与 `exec_ssh_command`，写明变更目的、影响范围与回滚方案），等待我在 ServerNeedSafe Web 端「执行审批」批准后，再通过 `wait_for_approval` / `get_approval_status` 查看每步执行回显并做只读复测核验。'
    );
  }

  lines.push(
    '4. 知识沉淀：若发现该主机的新服务、端口业务用途、典型故障根因或可复用 SOP，可调用 `update_host_memory`、`save_memory` 或 `save_runbook` 沉淀长期知识（严禁写入任何密码、私钥或 Token）。'
  );

  return lines.join('\n');
}
