import type { QQBotGatewayState, QQBotTargetType } from '../types';

export const QQ_INTENT_GROUP_AND_C2C = 1 << 25; // 33554432

export function hasIntentBit(mask: number, bitValue: number): boolean {
  return ((mask >>> 0) & (bitValue >>> 0)) !== 0;
}

export function toggleIntentBit(mask: number, bitValue: number, enabled: boolean): number {
  const cur = mask >>> 0;
  const val = bitValue >>> 0;
  if (enabled) {
    return (cur | val) >>> 0;
  }
  return (cur & ~val) >>> 0;
}

export function formatIntentMaskHex(mask: number): string {
  const u = mask >>> 0;
  return `0x${u.toString(16).toUpperCase()}`;
}

export function qqTargetTypeLabel(targetType: QQBotTargetType | string | undefined): string {
  switch (targetType) {
    case 'c2c':
      return 'QQ 单聊';
    case 'group':
      return 'QQ 群聊';
    case 'channel':
      return 'QQ 频道子频道';
    default:
      return targetType || '未知目标';
  }
}

export function qqPushCategoryLabel(category: string): string {
  switch (category) {
    case 'monitor_alert':
      return '状态监控告警';
    case 'ai_patrol':
      return 'AI 巡检异常';
    case 'external_approval':
      return '外部 AI 审批';
    case 'vuln_advisory':
      return '高危漏洞动态';
    case 'test':
      return '连通性测试';
    default:
      return category || '事件通知';
  }
}

export function qqGatewayStateMeta(state?: QQBotGatewayState | string): {
  label: string;
  tone: 'teal' | 'amber' | 'danger' | 'muted';
  online: boolean;
} {
  switch (state) {
    case 'connected':
      return { label: 'WebSocket 在线', tone: 'teal', online: true };
    case 'connecting':
      return { label: '正在握手连接', tone: 'amber', online: false };
    case 'identifying':
      return { label: '正在 Identify 鉴权', tone: 'amber', online: false };
    case 'resuming':
      return { label: '正在 Resume 恢复会话', tone: 'amber', online: false };
    case 'reconnecting':
      return { label: '断线自动重连中', tone: 'amber', online: false };
    case 'error':
      return { label: '配置或权限异常', tone: 'danger', online: false };
    case 'stopped_error':
      return { label: '已停止重连 (封禁/下架)', tone: 'danger', online: false };
    default:
      return { label: '未启用', tone: 'muted', online: false };
  }
}

export function maskQQIdentifier(raw: string): string {
  const s = (raw || '').trim();
  if (s.length <= 14) return s;
  return `${s.slice(0, 8)}…${s.slice(-6)}`;
}
