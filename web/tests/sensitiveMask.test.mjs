import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MASK_PLACEHOLDER,
  createSensitiveMasker,
  maskSensitiveText,
} from '../src/utils/sensitiveMask.ts';

test('masks IPv4, CIDR, IPv4:port, wildcard IPv4, IPv6, and MAC addresses to ***', () => {
  const input = [
    '主节点 192.168.1.10，内网网段 10.10.0.0/24，网关 127.0.0.1:18899',
    '放行网段 172.16.*.*，IPv6 [2001:db8::1]:443 与 fe80::1 及 ::1',
    '网卡 MAC 00:1a:2b:3c:4d:5e 监听 :::8080',
  ].join('\n');

  const out = maskSensitiveText(input);
  assert.doesNotMatch(out, /192\.168\.1\.10/);
  assert.doesNotMatch(out, /10\.10\.0\.0/);
  assert.doesNotMatch(out, /127\.0\.0\.1/);
  assert.doesNotMatch(out, /18899/);
  assert.doesNotMatch(out, /172\.16\.\*\.\*/);
  assert.doesNotMatch(out, /2001:db8::1/);
  assert.doesNotMatch(out, /fe80::1/);
  assert.doesNotMatch(out, /::1/);
  assert.doesNotMatch(out, /00:1a:2b:3c:4d:5e/);
  assert.doesNotMatch(out, /8080/);
  assert.match(out, /主节点 \*\*\*，内网网段 \*\*\*，网关 \*\*\*/);
});

test('masks Unix, home-relative, dot-relative, Windows paths, and sensitive server filenames', () => {
  const input = [
    '检查 /etc/nginx/conf.d/default.conf 和 /var/lib/postgresql/16/main 以及 /srv/app',
    '单级目录 /var 与 /opt 及 ~/.ssh/authorized_keys 与 ./docker-compose.yml',
    'Windows 路径 C:\\inetpub\\wwwroot\\web.config 和 D:/data/mysql/my.ini',
    '相对路径 conf.d/upstream.conf 与独立文件 sshd_config、auth.log、.env.production',
  ].join('\n');

  const out = maskSensitiveText(input);
  for (const leaked of [
    '/etc/nginx',
    'default.conf',
    '/var/lib/postgresql',
    '/srv/app',
    '/var',
    '/opt',
    'authorized_keys',
    'docker-compose.yml',
    'inetpub',
    'my.ini',
    'upstream.conf',
    'sshd_config',
    'auth.log',
    '.env.production',
  ]) {
    assert.equal(out.includes(leaked), false, `expected "${leaked}" to be masked in: ${out}`);
  }
  assert.ok(out.includes(MASK_PLACEHOLDER));
});

test('masks labeled ports, protocol ports, CLI port flags, bind ports, and HostMemory ports_note', () => {
  const masker = createSensitiveMasker();
  const prose = [
    '公网暴露默认 22 端口，内部放行 80、443、8080 端口，监听端口 8000-8090',
    '配置 port=5432, listen 443 ssl, tcp/6379, 53/udp, localhost:3000, *:9090',
    '执行 ssh -p 2222 deploy@prod-node && ufw allow 8443 && docker run -p 18899:8080 app',
    '工作日 09:00-21:00 与凌晨 03:00 严禁重启，版本 v2.7.1，CPU 85%',
  ].join('\n');

  const out = masker.maskText(prose);
  for (const leaked of ['22 ', '80、', '443', '8080', '8000-8090', '5432', '6379', '53/udp', '3000', '9090', '2222', '8443', '18899']) {
    assert.equal(out.includes(leaked), false, `expected port "${leaked}" to be masked in: ${out}`);
  }
  // Preserves non-port timestamps, software versions, and percentages
  assert.ok(out.includes('09:00-21:00'), `expected time window preserved: ${out}`);
  assert.ok(out.includes('03:00'), `expected timestamp preserved: ${out}`);
  assert.ok(out.includes('v2.7.1'), `expected version preserved: ${out}`);
  assert.ok(out.includes('85%'), `expected percentage preserved: ${out}`);

  const portsNote1 = masker.maskPortsNote(
    '[监控同步] 22(public:sshd), 80(public:nginx), 443(public:nginx), 18899(local:sns-server)'
  );
  assert.equal(
    portsNote1,
    '[监控同步] ***(public:sshd), ***(public:nginx), ***(public:nginx), ***(local:sns-server)'
  );

  const portsNote2 = masker.maskPortsNote(
    '443(公网HTTPS入口), 8080(内部管理API), 5432(仅内网PostgreSQL)'
  );
  assert.equal(
    portsNote2,
    '***(公网HTTPS入口), ***(内部管理API), ***(仅内网PostgreSQL)'
  );
});

test('masks URLs, connection strings, domains, emails, credentials, tokens, PEM blocks, and phone numbers', () => {
  const input = [
    '反代地址 https://admin.corp.example.com:8443/v1/login 与 db-master.internal:5432',
    'DSN: postgres://ops:SuperSecret99@10.0.1.5:5432/billing',
    '联系 alice.ops@company.com 手机 13812345678',
    'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    'API_KEY=sk-proj-1234567890abcdef1234567890 AWS AKIAIOSFODNN7EXAMPLE MCP sns_mcp_abcdef12345678',
    '管理员密码：MyDbPass#2026，Webhook 密钥为 wh_secret_987654',
    '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3NzaC1yc2EAAAADAQAB\n-----END OPENSSH PRIVATE KEY-----',
  ].join('\n');

  const out = maskSensitiveText(input);
  for (const leaked of [
    'admin.corp.example.com',
    'db-master.internal',
    'SuperSecret99',
    'alice.ops@company.com',
    '13812345678',
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
    'sk-proj-1234567890abcdef1234567890',
    'AKIAIOSFODNN7EXAMPLE',
    'sns_mcp_abcdef12345678',
    'MyDbPass#2026',
    'wh_secret_987654',
    'BEGIN OPENSSH PRIVATE KEY',
    'AAAAB3NzaC1yc2EAAAADAQAB',
  ]) {
    assert.equal(out.includes(leaked), false, `expected secret "${leaked}" to be masked in: ${out}`);
  }
});

test('masks sensitive Chinese and English vocabulary while preserving normal SRE instructions', () => {
  const agentsMd = `# ServerNeedSafe 全局运维智能体规范 (AGENTS.md)

## 1. 排查与诊断习惯
- **证据优先**：优先采用无损只读命令（\`ss\`、\`journalctl\`、\`systemctl status\`、\`df -h\`、\`free -m\`）取证。
- **零凭据泄漏**：禁止记录明文密码、SSH 私钥、API Key 或 Token。
- 严禁通过跳板机暴露 Root 口令或部署 xray / wireguard / frpc 内网穿透节点。`;

  const out = maskSensitiveText(agentsMd);
  assert.ok(out.includes('AGENTS.md'), `AGENTS.md title should be preserved: ${out}`);
  assert.ok(out.includes('`ss`'), `ss command should be preserved: ${out}`);
  assert.ok(out.includes('`systemctl status`'), `systemctl status should be preserved: ${out}`);
  assert.ok(out.includes('`df -h`'), `df -h should be preserved: ${out}`);

  for (const leaked of ['明文密码', '私钥', 'API Key', 'Token', '跳板机', 'Root', '口令', 'xray', 'wireguard', 'frpc', '内网穿透', '凭据']) {
    assert.equal(out.includes(leaked), false, `expected sensitive term "${leaked}" to be masked in: ${out}`);
  }
});

test('uses dynamic server inventory context to mask custom hosts, usernames, deploy paths, and custom SSH ports', () => {
  const masker = createSensitiveMasker({
    servers: [
      {
        host: 'bastion-internal-east',
        port: 22022,
        username: 'zezen_ops',
        default_path: '/custom/deploy-root',
      },
    ],
    hostMemories: [
      {
        deploy_paths: ['/srv/billing-core'],
      },
    ],
  });

  const text = '通过 bastion-internal-east 使用 zezen_ops 走 22022 登录，代码位于 /custom/deploy-root/api 与 /srv/billing-core';
  const out = masker.maskText(text);
  for (const leaked of ['bastion-internal-east', 'zezen_ops', '22022', '/custom/deploy-root', '/srv/billing-core']) {
    assert.equal(out.includes(leaked), false, `expected dynamic value "${leaked}" masked in: ${out}`);
  }

  assert.equal(masker.maskDeployPath('/srv/billing-core'), '***');
  assert.equal(masker.maskServiceName('container:billing-secret-api'), 'container:***');
  assert.equal(masker.maskServiceName('xray'), '***');
  assert.equal(masker.maskServiceName('nginx'), 'nginx');
});

test('masks env-style secret assignments, SSH config directives, and Chinese host/path labels', () => {
  const input = [
    'export MYSQL_ROOT_PASSWORD="SuperSecretPassword#1"',
    'BOT_TOKEN=123456:ABC-DEF9876',
    'REDIS_PASS=redis_secret_99',
    'HostName prod-db-01',
    'ProxyJump bastion-east',
    'IdentityFile ~/.ssh/prod_ed25519',
    '主机名：prod-core-01，数据目录：pgdata_prod',
    '配置在/etc/nginx/conf.d/app.conf中，访问prod.example.com或192.168.1.50',
  ].join('\n');

  const out = maskSensitiveText(input);
  for (const leaked of [
    'SuperSecretPassword#1',
    '123456:ABC-DEF9876',
    'redis_secret_99',
    'prod-db-01',
    'bastion-east',
    'prod_ed25519',
    'prod-core-01',
    'pgdata_prod',
    '/etc/nginx/conf.d/app.conf',
    'prod.example.com',
    '192.168.1.50',
  ]) {
    assert.equal(out.includes(leaked), false, `expected "${leaked}" masked in: ${out}`);
  }
  assert.ok(out.includes('配置在***中'), `expected adjacent Chinese prose preserved: ${out}`);
});

test('masks Chinese conjunction port lists, firewall-cmd ports, trailing slashes, docker mounts, key filenames, and SSH fingerprints', () => {
  const input = [
    '不要在公网开放 6379 和 3306，nginx 监听 80 与 443，firewall-cmd --add-port=8443',
    'scp -P 2222 prod-key.pem root@192.168.1.5:/data/backups/',
    'docker run -v /opt/serverneedsafe/data:/var/lib/mysql -p 18899:8080 app',
    '路径:/etc/nginx/conf.d，PATH=/usr/local/bin:/opt/tools',
    '主机指纹 SHA256:abcdef1234567890abcdef1234567890abcdef12345，配置文件 client.ovpn',
  ].join('\n');

  const out = maskSensitiveText(input);
  for (const leaked of [
    '6379',
    '3306',
    '80',
    '443',
    '8443',
    '2222',
    'prod-key.pem',
    '192.168.1.5',
    '/data/backups',
    '/opt/serverneedsafe',
    '/var/lib/mysql',
    '18899',
    '/etc/nginx',
    '/usr/local/bin',
    '/opt/tools',
    'abcdef1234567890',
    'client.ovpn',
  ]) {
    assert.equal(out.includes(leaked), false, `expected "${leaked}" masked in: ${out}`);
  }
  assert.equal(out.includes('***/'), false, `expected trailing slash absorbed cleanly: ${out}`);
});

test('maskMarkdownWithSentinel preserves bold markers around masked keys and avoids *** collision', () => {
  const masker = createSensitiveMasker();
  const md = '- **管理员密码**：Secret#999\n- 跳板机 10.0.0.1 端口 2222 需要核查';
  const { masked, sentinel } = masker.maskMarkdownWithSentinel(md);

  assert.equal(masked.includes('Secret#999'), false);
  assert.equal(masked.includes('10.0.0.1'), false);
  assert.equal(masked.includes('2222'), false);
  // Sentinel does not contain '*' so markdown **bold** tokenizer cannot misparse it
  assert.equal(sentinel.includes('*'), false);
  assert.ok(masked.includes(`**${sentinel}**`), `expected balanced bold markers: ${masked}`);

  // Plain-text maskText collapses **<sentinel>** cleanly to *** without ugly *******
  const plainMasked = masker.maskText(md);
  assert.equal(plainMasked, '- ***：***\n- *** *** 端口 *** 需要核查');
});

test('is idempotent, handles sentinel collisions, and preserves non-sensitive dates/versions/metrics', () => {
  const masker = createSensitiveMasker();
  const sample = [
    '发布日期 2026-11-27，维护窗口 09:00-21:00，凌晨 03:00 巡检',
    '系统 Ubuntu 22.04 / Debian 12 / Linux 6.1 x86_64，版本 v2.7.1',
    'CPU/内存/磁盘 阈值 85%，7×24 监控，重要度 4/5，延迟阈值 50MB',
    '含特殊占位符 \uE000SNS_MASK\uE001 与真实地址 10.20.30.40',
  ].join('\n');

  const once = masker.maskText(sample);
  const twice = masker.maskText(once);
  assert.equal(twice, once, 'maskText must be idempotent');

  assert.ok(once.includes('2026-11-27'));
  assert.ok(once.includes('09:00-21:00'));
  assert.ok(once.includes('03:00'));
  assert.ok(once.includes('Ubuntu 22.04'));
  assert.ok(once.includes('Debian 12'));
  assert.ok(once.includes('Linux 6.1 x86_64'));
  assert.ok(once.includes('v2.7.1'));
  assert.ok(once.includes('CPU/内存/磁盘'));
  assert.ok(once.includes('85%'));
  assert.ok(once.includes('7×24'));
  assert.ok(once.includes('4/5'));
  assert.ok(once.includes('50MB'));
  assert.ok(once.includes('\uE000SNS_MASK\uE001'), 'literal sentinel in input must not be corrupted');
  assert.equal(once.includes('10.20.30.40'), false);
  assert.equal(masker.maskText(''), '');
});
