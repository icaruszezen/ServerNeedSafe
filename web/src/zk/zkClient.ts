import wasmIntegrity from './wasmIntegrity.json';
import type { HostKeyUntrustedInfo, VaultAnchor } from '../types';

export interface WasmIntegrityState {
  verified: boolean;
  sha256: string;
  rawBytes: number;
  gzipBytes: number;
}

export class ZkRpcError extends Error {
  status: number;
  code: string;
  hostKeyInfo?: HostKeyUntrustedInfo;
  retryAfterSec?: number;

  constructor(
    message: string,
    status = 400,
    code = 'ERROR',
    hostKeyInfo?: HostKeyUntrustedInfo,
    retryAfterSec?: number
  ) {
    super(message);
    this.status = status;
    this.code = code;
    this.hostKeyInfo = hostKeyInfo;
    this.retryAfterSec = retryAfterSec;
  }
}

type PendingCall = {
  resolve: (val: { data: any; bytes?: Uint8Array }) => void;
  reject: (err: ZkRpcError) => void;
};

type TermSubscription = {
  onOutput: (chunk: Uint8Array) => void;
  onExit: (message: string) => void;
};

function anchorStorageKey(): string {
  return `sns_zk_anchor:${window.location.origin}`;
}

export function loadLocalAnchor(): VaultAnchor | null {
  try {
    const raw = localStorage.getItem(anchorStorageKey());
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed.vault_id === 'string' && parsed.vault_id) {
      return parsed as VaultAnchor;
    }
  } catch {
    // ignore corrupted storage
  }
  return null;
}

export function saveLocalAnchor(anchor?: VaultAnchor | null): void {
  try {
    if (!anchor || !anchor.vault_id) {
      return;
    }
    localStorage.setItem(anchorStorageKey(), JSON.stringify(anchor));
  } catch {
    // ignore storage quota errors
  }
}

export function clearLocalAnchorStorage(): void {
  try {
    localStorage.removeItem(anchorStorageKey());
  } catch {
    // ignore
  }
}

class ZeroKnowledgeWorkerClient {
  private worker: Worker | null = null;
  private nextId = 1;
  private pending = new Map<number, PendingCall>();
  private termSubs = new Map<string, TermSubscription>();
  private onAutoLocked: (() => void) | null = null;
  private integrity: WasmIntegrityState = {
    verified: false,
    sha256: wasmIntegrity.sha256,
    rawBytes: wasmIntegrity.rawBytes,
    gzipBytes: wasmIntegrity.gzipBytes,
  };
  private integrityListeners = new Set<(st: WasmIntegrityState) => void>();

  getIntegrityState(): WasmIntegrityState {
    return { ...this.integrity };
  }

  subscribeIntegrity(fn: (st: WasmIntegrityState) => void): () => void {
    this.integrityListeners.add(fn);
    fn(this.getIntegrityState());
    return () => {
      this.integrityListeners.delete(fn);
    };
  }

  setOnAutoLocked(fn: (() => void) | null): void {
    this.onAutoLocked = fn;
  }

  private ensureWorker(): Worker {
    if (this.worker) return this.worker;

    const w = new Worker(new URL('./zkWorker.ts', import.meta.url), {
      type: 'module',
      name: 'sns-zero-knowledge-enclave',
    });

    w.onmessage = (ev: MessageEvent) => {
      const msg = ev.data;
      if (!msg || typeof msg !== 'object') return;

      if (msg.kind === 'wasm_verified') {
        this.integrity = {
          verified: true,
          sha256: msg.sha256,
          rawBytes: msg.rawBytes,
          gzipBytes: msg.gzipBytes,
        };
        for (const fn of this.integrityListeners) {
          fn(this.getIntegrityState());
        }
        return;
      }

      if (msg.kind === 'vault_locked') {
        this.destroyWorkerMemory();
        this.onAutoLocked?.();
        return;
      }

      if (msg.kind === 'anchor_updated' && typeof msg.anchorJson === 'string') {
        try {
          const anchor = JSON.parse(msg.anchorJson);
          if (anchor?.vault_id) {
            saveLocalAnchor(anchor);
          }
        } catch {
          // ignore
        }
        return;
      }

      if (msg.kind === 'term_output') {
        const sub = this.termSubs.get(msg.tabId);
        if (sub && msg.bytes instanceof Uint8Array) {
          sub.onOutput(msg.bytes);
        }
        return;
      }

      if (msg.kind === 'term_exit') {
        const sub = this.termSubs.get(msg.tabId);
        if (sub) {
          sub.onExit(msg.message || '会话已结束');
        }
        return;
      }

      if (msg.kind === 'rpc_resp') {
        const entry = this.pending.get(msg.id);
        if (!entry) return;
        this.pending.delete(msg.id);

        if (!msg.ok) {
          let hk: HostKeyUntrustedInfo | undefined;
          if (msg.hostKeyJson) {
            try {
              hk = JSON.parse(msg.hostKeyJson);
            } catch {
              // ignore
            }
          }
          entry.reject(
            new ZkRpcError(
              msg.error || '零知识引擎操作失败',
              msg.status || 400,
              msg.code || 'ERROR',
              hk,
              msg.retryAfterSec
            )
          );
          return;
        }

        let parsed: any = {};
        if (msg.json) {
          try {
            parsed = JSON.parse(msg.json);
          } catch {
            parsed = {};
          }
        }
        if (parsed?.anchor?.vault_id) {
          saveLocalAnchor(parsed.anchor);
        }
        entry.resolve({ data: parsed, bytes: msg.bytes });
      }
    };

    w.onerror = (err) => {
      for (const [, p] of this.pending) {
        p.reject(new ZkRpcError(err.message || 'Web Worker 运行异常', 500, 'WORKER_CRASH'));
      }
      this.pending.clear();
    };

    this.worker = w;
    return w;
  }

  async call<T = any>(action: string, payload?: unknown, binary?: Uint8Array): Promise<T> {
    const res = await this.callWithBytes<T>(action, payload, binary);
    return res.data;
  }

  async callWithBytes<T = any>(
    action: string,
    payload?: unknown,
    binary?: Uint8Array
  ): Promise<{ data: T; bytes?: Uint8Array }> {
    const w = this.ensureWorker();
    const id = this.nextId++;
    const payloadJson = payload !== undefined ? JSON.stringify(payload) : '{}';
    const anchor = loadLocalAnchor();

    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      if (binary && binary.byteLength > 0) {
        const copy = new Uint8Array(binary.byteLength);
        copy.set(binary);
        w.postMessage(
          {
            kind: 'rpc',
            id,
            action,
            payloadJson,
            bytes: copy,
            origin: window.location.origin,
            anchor,
          },
          [copy.buffer]
        );
      } else {
        w.postMessage({
          kind: 'rpc',
          id,
          action,
          payloadJson,
          origin: window.location.origin,
          anchor,
        });
      }
    });
  }

  subscribeTerminal(tabId: string, sub: TermSubscription): () => void {
    this.termSubs.set(tabId, sub);
    return () => {
      this.termSubs.delete(tabId);
    };
  }

  sendTerminalInput(tabId: string, textOrBytes: string | Uint8Array): void {
    if (!this.worker) return;
    const bytes =
      typeof textOrBytes === 'string' ? new TextEncoder().encode(textOrBytes) : textOrBytes;
    if (bytes.byteLength === 0) return;
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);
    this.worker.postMessage({ kind: 'term_input', tabId, bytes: copy }, [copy.buffer]);
  }

  resizeTerminal(tabId: string, cols: number, rows: number): void {
    if (!this.worker) return;
    this.worker.postMessage({ kind: 'term_resize', tabId, cols, rows });
  }

  closeTerminal(tabId: string): void {
    this.termSubs.delete(tabId);
    if (!this.worker) return;
    this.worker.postMessage({ kind: 'term_close', tabId });
  }

  // Terminates the Dedicated Web Worker to immediately unmap its entire WASM linear memory
  // (wiping DEK, AuthPrivateKey, and decrypted VaultState from browser process heap).
  destroyWorkerMemory(): void {
    for (const [, sub] of this.termSubs) {
      sub.onExit('保险库已锁定，安全终端内存已销毁');
    }
    this.termSubs.clear();
    for (const [, p] of this.pending) {
      p.reject(new ZkRpcError('保险库已锁定', 401, 'VAULT_LOCKED'));
    }
    this.pending.clear();
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
  }
}

export const zkClient = new ZeroKnowledgeWorkerClient();
