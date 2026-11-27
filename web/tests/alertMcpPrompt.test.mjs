import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webDir = path.resolve(__dirname, '..');

test('buildAlertMCPPrompt prefers backend mcp_prompt and constructs rich MCP fallback prompts', async () => {
  const vite = await createServer({
    root: webDir,
    logLevel: 'silent',
    server: { middlewareMode: true },
    appType: 'custom',
  });

  try {
    const { buildAlertMCPPrompt } = await vite.ssrLoadModule('/src/utils/alertMcpPrompt.ts');

    // 1. Prefers backend-generated advice.mcp_prompt when present
    const withBackend = buildAlertMCPPrompt({
      id: 'al-1',
      dedup_key: 'srv-1|cpu_high|',
      server_id: 'srv-1',
      server_name: 'prod-web-01',
      host: '10.0.0.1:22',
      rule_kind: 'cpu_high',
      rule_name: 'CPU 高占用',
      severity: 'critical',
      status: 'firing',
      title: 'CPU 飙升 95%',
      detail: '连续 3 次超阈值',
      metric_text: '95%',
      occurrences: 3,
      triggered_at: '2026-11-27T10:00:00Z',
      last_seen_at: '2026-11-27T10:05:00Z',
      advice: {
        summary: 'CPU 高占用',
        mcp_prompt: '  BACKEND_CANONICAL_MCP_PROMPT  ',
      },
    });
    assert.equal(withBackend, 'BACKEND_CANONICAL_MCP_PROMPT');

    // 2. Fallback generates full structured prompt when advice.mcp_prompt is absent
    const fallbackLinux = buildAlertMCPPrompt(
      {
        id: 'al-disk',
        dedup_key: 'srv-db|disk_high|/var/log',
        server_id: 'srv-db',
        server_name: 'prod-db-01',
        host: '10.10.0.2:22',
        rule_kind: 'disk_high',
        rule_name: '磁盘空间高水位',
        severity: 'critical',
        status: 'firing',
        title: '[prod-db-01] 磁盘 /var/log 使用率 94%',
        detail: '可用空间不足 6 GB',
        metric_text: '94.0%',
        threshold_text: '>= 90%',
        occurrences: 4,
        triggered_at: '2026-11-27T10:00:00Z',
        last_seen_at: '2026-11-27T10:15:00Z',
        advice: {
          summary: '/var/log 分区逼近满载',
          evidence: ['分区 /var/log 已用 94.0 / 100 GB'],
          commands: [
            {
              label: '定位大文件',
              command: 'du -xh --max-depth=2 /var/log | sort -rh | head -n 15',
              risk: 'readonly',
            },
            {
              label: '清理旧日志',
              command: 'sudo journalctl --vacuum-time=7d',
              risk: 'mutating',
            },
          ],
          runbooks: [{ id: 'rb-log', title: '磁盘日志清理 SOP' }],
          quick_actions: [{ kind: 'accept_port_baseline', label: '采纳当前端口基线' }],
        },
      },
      {
        id: 'srv-db',
        name: 'prod-db-01',
        group: '核心数据库',
        tags: ['postgres'],
        host: '10.10.0.2',
        port: 22,
        username: 'root',
        auth_type: 'key',
        has_password: false,
        has_private_key: true,
        has_passphrase: false,
        pinned: false,
        keep_alive_sec: 30,
        last_os_info: 'Ubuntu 24.04',
        created_at: '2026-11-01T00:00:00Z',
        updated_at: '2026-11-01T00:00:00Z',
      }
    );

    for (const token of [
      'ServerNeedSafe MCP（`serverneedsafe`）',
      'server_id: `srv-db`',
      '所属分组：核心数据库',
      'Ubuntu 24.04',
      'get_ops_context(server_ids=["srv-db"])',
      'get_server_detail(server_id="srv-db", range="1h")',
      'exec_readonly_ssh(server_ids=["srv-db"], ...)',
      'du -xh --max-depth=2 /var/log | sort -rh | head -n 15',
      'sudo journalctl --vacuum-time=7d',
      '`rb-log` — 磁盘日志清理 SOP',
      '采纳当前端口基线',
      'propose_change_plan',
      'wait_for_approval',
    ]) {
      assert.ok(fallbackLinux.includes(token), `expected fallback prompt to include ${token}`);
    }

    // 3. macOS server adds BSD/macOS compatibility note
    const macPrompt = buildAlertMCPPrompt(
      {
        id: 'al-mac',
        dedup_key: 'srv-mac|cpu_high|',
        server_id: 'srv-mac',
        server_name: 'mac-mini',
        host: '10.0.0.9:22',
        rule_kind: 'cpu_high',
        rule_name: 'CPU 高占用',
        severity: 'warning',
        status: 'firing',
        title: 'CPU 92%',
        detail: '高占用',
        metric_text: '92%',
        occurrences: 1,
        triggered_at: '2026-11-27T10:00:00Z',
        last_seen_at: '2026-11-27T10:00:00Z',
      },
      {
        id: 'srv-mac',
        name: 'mac-mini',
        group: '研发',
        tags: ['macos'],
        host: '10.0.0.9',
        port: 22,
        username: 'admin',
        auth_type: 'key',
        has_password: false,
        has_private_key: true,
        has_passphrase: false,
        pinned: false,
        keep_alive_sec: 30,
        last_os_info: 'macOS 15.1 (Darwin)',
        created_at: '2026-11-01T00:00:00Z',
        updated_at: '2026-11-01T00:00:00Z',
      }
    );
    assert.ok(macPrompt.includes('BSD/macOS'));

    // 4. Offline & host_key_changed tailor step 2 safely
    const offlinePrompt = buildAlertMCPPrompt({
      id: 'al-off',
      dedup_key: 'srv-off|offline|',
      server_id: 'srv-off',
      server_name: 'edge-01',
      host: '10.0.0.5:22',
      rule_kind: 'offline',
      rule_name: '主机离线',
      severity: 'critical',
      status: 'firing',
      title: 'SSH 不可达',
      detail: 'timeout',
      metric_text: '离线',
      occurrences: 2,
      triggered_at: '2026-11-27T10:00:00Z',
      last_seen_at: '2026-11-27T10:05:00Z',
    });
    assert.ok(offlinePrompt.includes('probe_server(server_id="srv-off")'));

    const hostKeyPrompt = buildAlertMCPPrompt({
      id: 'al-hk',
      dedup_key: 'srv-hk|host_key_changed|',
      server_id: 'srv-hk',
      server_name: 'edge-02',
      host: '10.0.0.6:22',
      rule_kind: 'host_key_changed',
      rule_name: 'SSH 指纹变化',
      severity: 'critical',
      status: 'firing',
      title: '主机公钥指纹变更',
      detail: 'mismatch',
      metric_text: '已拦截',
      occurrences: 1,
      triggered_at: '2026-11-27T10:00:00Z',
      last_seen_at: '2026-11-27T10:00:00Z',
    });
    assert.ok(hostKeyPrompt.includes('切勿尝试绕过或忽略 SSH 主机指纹校验'));

    // 5. Resolved alert switches to post-mortem wording and includes resolved_at
    const resolvedPrompt = buildAlertMCPPrompt({
      id: 'al-res',
      dedup_key: 'srv-1|mem_high|',
      server_id: 'srv-1',
      server_name: 'prod-web-01',
      host: '10.0.0.1:22',
      rule_kind: 'mem_high',
      rule_name: '内存高占用',
      severity: 'warning',
      status: 'resolved',
      title: '内存使用率 91%',
      detail: '已回落',
      metric_text: '91%',
      occurrences: 2,
      triggered_at: '2026-11-27T09:00:00Z',
      last_seen_at: '2026-11-27T09:20:00Z',
      resolved_at: '2026-11-27T09:25:00Z',
    });
    assert.ok(resolvedPrompt.includes('复盘以下已恢复的服务器监控告警'));
    assert.ok(resolvedPrompt.includes('恢复时间：2026-11-27T09:25:00Z'));

    // 6. Missing server_id falls back to list_servers instruction & safely handles backticks
    const missingSid = buildAlertMCPPrompt({
      id: 'al-nosid',
      dedup_key: '',
      server_id: '',
      server_name: 'orphan-host',
      host: '10.0.0.99:22',
      rule_kind: 'cpu_high',
      rule_name: 'CPU 高占用',
      severity: 'warning',
      status: 'firing',
      title: 'CPU 90%',
      detail: 'high',
      metric_text: '90%',
      occurrences: 1,
      triggered_at: '2026-11-27T09:00:00Z',
      last_seen_at: '2026-11-27T09:00:00Z',
      advice: {
        summary: '检查 `worker`',
        commands: [{ label: '测试命令', command: 'echo `hostname`', risk: 'readonly' }],
      },
    });
    assert.ok(missingSid.includes('先调用 `list_servers`'));
    assert.ok(missingSid.includes('`` echo `hostname` ``'));
  } finally {
    await vite.close();
  }
});
