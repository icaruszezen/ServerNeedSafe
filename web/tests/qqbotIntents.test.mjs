import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webDir = path.resolve(__dirname, '..');

test('qqbotIntents helpers compute unsigned 32-bit QQ Gateway intents bitmasks and labels cleanly', async () => {
  const vite = await createServer({
    root: webDir,
    logLevel: 'silent',
    server: { middlewareMode: true },
    appType: 'custom',
  });

  try {
    const mod = await vite.ssrLoadModule('/src/utils/qqbotIntents.ts');
    const GROUP_C2C = 1 << 25;
    const PUBLIC_GUILD = 1 << 30;
    const GUILDS = 1 << 0;

    assert.equal(mod.QQ_INTENT_GROUP_AND_C2C, 33554432);
    assert.equal(mod.hasIntentBit(GROUP_C2C, GROUP_C2C), true);
    assert.equal(mod.hasIntentBit(GROUP_C2C, PUBLIC_GUILD), false);

    // Enabling high bit (1 << 30) stays positive unsigned 32-bit integer
    const combined = mod.toggleIntentBit(GROUP_C2C, PUBLIC_GUILD, true);
    assert.equal(combined, (GROUP_C2C | PUBLIC_GUILD) >>> 0);
    assert.equal(mod.hasIntentBit(combined, PUBLIC_GUILD), true);
    assert.equal(mod.hasIntentBit(combined, GROUP_C2C), true);

    const withGuilds = mod.toggleIntentBit(combined, GUILDS, true);
    assert.equal(mod.formatIntentMaskHex(withGuilds), '0x42000001');

    const removed = mod.toggleIntentBit(withGuilds, PUBLIC_GUILD, false);
    assert.equal(mod.hasIntentBit(removed, PUBLIC_GUILD), false);
    assert.equal(mod.hasIntentBit(removed, GROUP_C2C), true);

    assert.equal(mod.qqTargetTypeLabel('c2c'), 'QQ 单聊');
    assert.equal(mod.qqTargetTypeLabel('group'), 'QQ 群聊');
    assert.equal(mod.qqTargetTypeLabel('channel'), 'QQ 频道子频道');

    assert.equal(mod.qqPushCategoryLabel('monitor_alert'), '状态监控告警');
    assert.equal(mod.qqPushCategoryLabel('external_approval'), '外部 AI 审批');

    assert.deepEqual(mod.qqGatewayStateMeta('connected'), {
      label: 'WebSocket 在线',
      tone: 'teal',
      online: true,
    });
    assert.equal(mod.qqGatewayStateMeta('error').tone, 'danger');
    assert.equal(mod.qqGatewayStateMeta('reconnecting').tone, 'amber');
    assert.equal(mod.qqGatewayStateMeta('disabled').tone, 'muted');

    assert.equal(
      mod.maskQQIdentifier('A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4'),
      'A1B2C3D4…B2C3D4'
    );
    assert.equal(mod.maskQQIdentifier('short-id'), 'short-id');
  } finally {
    await vite.close();
  }
});
