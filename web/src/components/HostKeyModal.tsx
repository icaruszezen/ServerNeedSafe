import React from 'react';
import { ShieldAlert, ShieldQuestion, X } from 'lucide-react';
import type { HostKeyUntrustedInfo } from '../types';

interface HostKeyModalProps {
  info: HostKeyUntrustedInfo;
  onTrustAndRetry: (fingerprint: string) => void;
  onCancel: () => void;
}

export const HostKeyModal: React.FC<HostKeyModalProps> = ({
  info,
  onTrustAndRetry,
  onCancel,
}) => {
  const isMismatch = info.reason === 'mismatch';

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true">
      <div className="modal-panel" id="hostkey-verify-modal">
        <div className="modal-header">
          <h3 style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {isMismatch ? (
              <ShieldAlert size={18} style={{ color: 'var(--danger-text)' }} />
            ) : (
              <ShieldQuestion size={18} style={{ color: 'var(--amber-text)' }} />
            )}
            {isMismatch ? '高危警报：SSH 主机密钥指纹变更' : '核验远程服务器 SSH 主机指纹'}
          </h3>
          <button type="button" className="btn btn-ghost btn-sm btn-icon" onClick={onCancel}>
            <X size={16} />
          </button>
        </div>

        <div className="modal-body">
          <div className={`alert ${isMismatch ? 'alert-error' : 'alert-warn'}`}>
            <span>
              {isMismatch
                ? '目标服务器返回的公钥与加密保险库中已固定的信任指纹不一致！这可能意味着服务器重装了系统，或连接正在遭受中间人 (MITM) 劫持攻击。'
                : '首次连接该主机，请确认以下 SSH 公钥指纹与目标服务器一致，信任后将加密固定在安全保险库中。'}
            </span>
          </div>

          <div className="kv-list">
            <div className="kv-row">
              <span className="kv-key">服务器名称</span>
              <span className="kv-val">{info.server_name}</span>
            </div>
            <div className="kv-row">
              <span className="kv-key">远程地址</span>
              <span className="kv-val">{info.address}</span>
            </div>
            <div className="kv-row">
              <span className="kv-key">算法类型</span>
              <span className="kv-val">{info.key_type}</span>
            </div>
            {info.expected_fingerprint && (
              <div className="kv-row">
                <span className="kv-key">原信任指纹</span>
                <span className="kv-val" style={{ color: 'var(--text-muted)' }}>
                  {info.expected_fingerprint}
                </span>
              </div>
            )}
            <div className="kv-row">
              <span className="kv-key">当前呈现指纹</span>
              <span
                className="kv-val"
                style={{
                  color: isMismatch ? 'var(--danger-text)' : 'var(--accent-teal)',
                  fontWeight: 600,
                }}
              >
                {info.presented_fingerprint}
              </span>
            </div>
          </div>
        </div>

        <div className="modal-footer">
          <button type="button" className="btn" onClick={onCancel}>
            拒绝并断开
          </button>
          <button
            type="button"
            id="hostkey-trust-confirm-btn"
            className={`btn ${isMismatch ? 'btn-danger' : 'btn-primary'}`}
            onClick={() => onTrustAndRetry(info.presented_fingerprint)}
          >
            {isMismatch ? '确认重装无误，更新信任指纹' : '信任该主机指纹并继续'}
          </button>
        </div>
      </div>
    </div>
  );
};
