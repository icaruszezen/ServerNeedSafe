import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createServer } from 'vite';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webDir = path.resolve(__dirname, '..');

test('FormattedMarkdownText + AIMemoryAgentsTab render masking and default-OFF state cleanly', async () => {
  const vite = await createServer({
    root: webDir,
    logLevel: 'silent',
    server: { middlewareMode: true },
    appType: 'custom',
  });

  try {
    const { FormattedMarkdownText } = await vite.ssrLoadModule('/src/components/AIMessageWidgets.tsx');
    const { AIMemoryAgentsTab } = await vite.ssrLoadModule('/src/components/AIMemoryAgentsTab.tsx');
    const { createSensitiveMasker } = await vite.ssrLoadModule('/src/utils/sensitiveMask.ts');

    // 1. FormattedMarkdownText preserves bold/code formatting when rendering masked Markdown via sentinel
    const masker = createSensitiveMasker({
      servers: [
        {
          host: '192.168.88.10',
          port: 22022,
          username: 'zezen_ops',
          default_path: '/srv/billing-core',
        },
      ],
    });
    const sampleMd = [
      '# 运维规范 (AGENTS.md)',
      '- **管理员密码**：MyPass#2026',
      '- 跳板机 10.10.2.20 端口 18899 配置 `/etc/nginx/conf.d/prod.conf`',
      '```bash',
      'ssh -p 22022 zezen_ops@192.168.88.10',
      'curl https://admin.corp.example.com:8443/v1',
      '```',
    ].join('\n');

    const { masked, sentinel } = masker.maskMarkdownWithSentinel(sampleMd);
    const mdHtml = renderToStaticMarkup(
      React.createElement(FormattedMarkdownText, { text: masked, maskSentinel: sentinel })
    );

    assert.ok(mdHtml.includes('AGENTS.md'), 'AGENTS.md heading preserved');
    assert.ok(mdHtml.includes('<strong>***</strong>：***'), `bold masked key preserved: ${mdHtml}`);
    assert.ok(mdHtml.includes('*** *** 端口 *** 配置 '), `inline multi-*** not mangled by bold parser: ${mdHtml}`);
    assert.ok(mdHtml.includes('>***</code>'), `inline code path masked cleanly: ${mdHtml}`);
    assert.ok(mdHtml.includes('ssh -p *** ***'), `code block command masked cleanly: ${mdHtml}`);
    assert.ok(mdHtml.includes('curl ***'), `code block URL masked cleanly: ${mdHtml}`);
    for (const leaked of [
      'MyPass#2026',
      '10.10.2.20',
      '18899',
      '/etc/nginx/conf.d/prod.conf',
      '22022',
      'zezen_ops',
      '192.168.88.10',
      'admin.corp.example.com',
      '跳板机',
      '管理员密码',
    ]) {
      assert.equal(mdHtml.includes(leaked), false, `expected "${leaked}" not leaked in HTML: ${mdHtml}`);
    }

    // 2. AIMemoryAgentsTab defaults to OFF (aria-pressed="false", no active banner, plaintext visible)
    const noopAsync = async () => {};
    const sampleOverview = {
      providers: [],
      active_provider_id: '',
      presets: [],
      default_mode: 'standard',
      agents_md: {
        enabled: true,
        content: sampleMd,
        revision: 3,
        updated_at: '2026-11-27T08:00:00Z',
      },
      agents_md_template: '',
      memory_config: {
        agents_md_max_chars: 6000,
        memory_prompt_budget_chars: 4500,
        compaction_trigger_ratio: 0.7,
        compaction_keep_recent: 6,
        auto_sync_monitor_to_memory: true,
        auto_record_approved_changes: true,
      },
      sessions: [],
      memories: [
        {
          id: 'mem-1',
          scope: 'global',
          server_ids: [],
          category: 'topology',
          title: '主库 10.10.2.20 拓扑',
          content: '端口 5432，目录 /var/lib/postgresql',
          tags: ['postgres'],
          pinned: false,
          importance: 4,
          source: 'manual',
          use_count: 1,
          created_at: '2026-11-27T08:00:00Z',
          updated_at: '2026-11-27T08:00:00Z',
        },
      ],
      host_memories: [
        {
          server_id: 'srv-1',
          server_name: 'hk-prod-gw-01',
          summary: '网关 192.168.88.10',
          os_arch: 'Debian 12 / Linux 6.1 x86_64',
          key_services: ['nginx', 'container:secret-pay-api'],
          deploy_paths: ['/etc/nginx/conf.d', '/srv/billing-core'],
          ports_note: '443(公网HTTPS入口), 8080(内部管理API)',
          constraints: '工作日 09:00-21:00 严禁重启',
          notes: '私钥 ~/.ssh/id_ed25519',
          auto_updated_count: 1,
          updated_at: '2026-11-27T08:00:00Z',
        },
      ],
      runbooks: [
        {
          id: 'rb-1',
          title: 'SSH 暴力破解排查 SOP',
          category: '安全加固',
          tags: ['SSH'],
          symptom: 'auth.log 出现高频扫描 IP',
          root_cause: '暴露 22 端口',
          diagnostic_steps: [],
          fix_commands: ['sshd -t && systemctl reload sshd'],
          created_at: '2026-11-27T08:00:00Z',
          updated_at: '2026-11-27T08:00:00Z',
        },
      ],
      patrol_config: {
        enabled: false,
        interval_minutes: 60,
        server_ids: [],
        cpu_warn_percent: 85,
        mem_warn_percent: 85,
        disk_warn_percent: 85,
        ssh_fail_warn_count: 15,
        check_listening_ports: true,
        check_privileged_users: true,
        webhooks: [],
      },
      patrol_status: { running: false, unread_alerts: 0 },
      patrol_records: [],
      mcp_config: {
        enabled: false,
        endpoint_path: '/api/mcp',
        allow_mutating_proposals: false,
        approval_ttl_minutes: 30,
        tokens: [],
      },
      pending_external_approvals: 0,
    };

    const servers = [
      {
        id: 'srv-1',
        name: 'hk-prod-gw-01',
        group: '生产',
        tags: [],
        host: '192.168.88.10',
        port: 22022,
        username: 'zezen_ops',
        auth_type: 'key',
        has_password: false,
        has_private_key: true,
        has_passphrase: false,
        default_path: '/srv/billing-core',
        pinned: false,
        keep_alive_sec: 30,
      },
    ];

    const renderSection = (initialSection, initialMaskSensitive) =>
      renderToStaticMarkup(
        React.createElement(AIMemoryAgentsTab, {
          overview: sampleOverview,
          servers,
          initialSection,
          ...(initialMaskSensitive === undefined ? {} : { initialMaskSensitive }),
          onReloadOverview: noopAsync,
          onRefreshWorkspace: noopAsync,
          onLaunchRunbook: noopAsync,
          onNotify: () => {},
        })
      );

    // 2. Default state is strictly OFF (aria-pressed="false", no banner, plaintext visible)
    const defaultHostsHtml = renderSection('hosts');
    assert.ok(defaultHostsHtml.includes('id="ai-memory-mask-sensitive-btn"'));
    assert.ok(defaultHostsHtml.includes('aria-pressed="false"'));
    assert.ok(defaultHostsHtml.includes('一键屏蔽关键信息'));
    assert.equal(defaultHostsHtml.includes('id="ai-memory-mask-banner"'), false);
    assert.ok(defaultHostsHtml.includes('/etc/nginx/conf.d'));
    assert.ok(defaultHostsHtml.includes('443(公网HTTPS入口)'));
    assert.ok(defaultHostsHtml.includes('192.168.88.10'));

    // 3. Masked ON state across all 4 sections of Agent & Memory Center
    const maskedAgentsHtml = renderSection('agents_md', true);
    assert.ok(maskedAgentsHtml.includes('aria-pressed="true"'));
    assert.ok(maskedAgentsHtml.includes('已屏蔽关键信息'));
    assert.ok(maskedAgentsHtml.includes('id="ai-memory-mask-banner"'));
    assert.ok(maskedAgentsHtml.includes('导出脱敏 AGENTS.md'));
    assert.ok(maskedAgentsHtml.includes('readonly=""') || maskedAgentsHtml.includes('readOnly'));
    assert.ok(maskedAgentsHtml.includes('disabled=""'));
    for (const leaked of [
      'MyPass#2026',
      '10.10.2.20',
      '18899',
      '/etc/nginx/conf.d/prod.conf',
      '192.168.88.10',
      '22022',
      'zezen_ops',
      'admin.corp.example.com',
      '跳板机',
    ]) {
      assert.equal(maskedAgentsHtml.includes(leaked), false, `agents_md leaked "${leaked}"`);
    }
    assert.ok(maskedAgentsHtml.includes('<strong>***</strong>：***'));

    const maskedMemoriesHtml = renderSection('memories', true);
    assert.ok(maskedMemoriesHtml.includes('id="ai-memory-mask-banner"'));
    for (const leaked of ['10.10.2.20', '5432', '/var/lib/postgresql']) {
      assert.equal(maskedMemoriesHtml.includes(leaked), false, `memories leaked "${leaked}"`);
    }
    assert.ok(maskedMemoriesHtml.includes('#postgres'));
    assert.ok(maskedMemoriesHtml.includes('***'));

    const maskedHostsHtml = renderSection('hosts', true);
    for (const leaked of [
      '192.168.88.10',
      '/etc/nginx/conf.d',
      '/srv/billing-core',
      '443',
      '8080',
      'secret-pay-api',
      '~/.ssh/id_ed25519',
      '私钥',
    ]) {
      assert.equal(maskedHostsHtml.includes(leaked), false, `hosts leaked "${leaked}"`);
    }
    assert.ok(maskedHostsHtml.includes('***(公网HTTPS入口), ***(内部管理API)'));
    assert.ok(maskedHostsHtml.includes('container:***'));
    assert.ok(maskedHostsHtml.includes('Debian 12 / Linux 6.1 x86_64'));
    assert.ok(maskedHostsHtml.includes('09:00-21:00'));

    const maskedRunbooksHtml = renderSection('runbooks', true);
    for (const leaked of ['暴力破解', 'auth.log', '22 端口']) {
      assert.equal(maskedRunbooksHtml.includes(leaked), false, `runbooks leaked "${leaked}"`);
    }
    assert.ok(maskedRunbooksHtml.includes('*** 端口'));
  } finally {
    await vite.close();
  }
});
