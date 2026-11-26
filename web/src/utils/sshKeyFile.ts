export const MAX_PRIVATE_KEY_FILE_BYTES = 256 * 1024;
export const MAX_PUBLIC_KEY_FILE_BYTES = 64 * 1024;

export interface ParsedPrivateKeyFile {
  file: File;
  fileName: string;
  fileSize: number;
  content: string;
  formatLabel: string;
  keyTypeHint?: string;
  encrypted: boolean;
  suggestedName: string;
}

export interface ParsedPublicKeyFile {
  file: File;
  fileName: string;
  fileSize: number;
  content: string;
  keyTypeLabel: string;
}

export class KeyFileValidationError extends Error {
  readonly code: 'TOO_LARGE' | 'BINARY' | 'EMPTY' | 'PUTTY_PPK' | 'IS_PUBLIC_KEY' | 'INVALID_FORMAT';

  constructor(
    message: string,
    code: 'TOO_LARGE' | 'BINARY' | 'EMPTY' | 'PUTTY_PPK' | 'IS_PUBLIC_KEY' | 'INVALID_FORMAT'
  ) {
    super(message);
    this.name = 'KeyFileValidationError';
    this.code = code;
  }
}

const PUBLIC_KEY_PREFIXES = [
  'ssh-ed25519 ',
  'ssh-rsa ',
  'ssh-dss ',
  'ecdsa-sha2-',
  'sk-ssh-ed25519@',
  'sk-ecdsa-sha2-',
];

export function formatKeyFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

export function normalizeKeyText(raw: string): string {
  return raw
    .replace(/^\uFEFF/, '')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .trim();
}

export function looksLikePublicKeyText(text: string): boolean {
  const trimmed = normalizeKeyText(text);
  return PUBLIC_KEY_PREFIXES.some((prefix) => trimmed.startsWith(prefix));
}

export function suggestCredentialName(fileName: string): string {
  const base = fileName.split(/[\\/]/).pop()?.trim() || '';
  if (!base) return '';
  const stripped = base.replace(/\.(pem|key|pri|openssh|txt)$/i, '');
  return stripped || base;
}

function readWireString(buf: Uint8Array, offset: number): { value: Uint8Array; next: number } | null {
  if (offset + 4 > buf.length) return null;
  const len =
    ((buf[offset] << 24) >>> 0) |
    (buf[offset + 1] << 16) |
    (buf[offset + 2] << 8) |
    buf[offset + 3];
  const start = offset + 4;
  const end = start + len;
  if (end > buf.length) return null;
  return { value: buf.subarray(start, end), next: end };
}

function mapSSHKeyTypeLabel(rawType: string): string | undefined {
  switch (rawType) {
    case 'ssh-ed25519':
      return 'Ed25519';
    case 'ssh-rsa':
      return 'RSA';
    case 'ecdsa-sha2-nistp256':
      return 'ECDSA-P256';
    case 'ecdsa-sha2-nistp384':
      return 'ECDSA-P384';
    case 'ecdsa-sha2-nistp521':
      return 'ECDSA-P521';
    case 'sk-ssh-ed25519@openssh.com':
      return 'SK-Ed25519';
    case 'sk-ecdsa-sha2-nistp256@openssh.com':
      return 'SK-ECDSA';
    default:
      return undefined;
  }
}

function inspectOpenSSHMetadata(pemText: string): { encrypted: boolean; keyTypeHint?: string } {
  try {
    const match = pemText.match(
      /-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]+?)-----END OPENSSH PRIVATE KEY-----/
    );
    if (!match) return { encrypted: false };
    const b64 = match[1].replace(/\s+/g, '');
    const binary = atob(b64);
    const buf = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      buf[i] = binary.charCodeAt(i);
    }
    const magic = 'openssh-key-v1\0';
    if (buf.length < magic.length + 16) return { encrypted: false };
    for (let i = 0; i < magic.length; i++) {
      if (buf[i] !== magic.charCodeAt(i)) return { encrypted: false };
    }
    const decoder = new TextDecoder('ascii');
    const cipherField = readWireString(buf, magic.length);
    if (!cipherField) return { encrypted: false };
    const cipherName = decoder.decode(cipherField.value);
    const kdfField = readWireString(buf, cipherField.next);
    if (!kdfField) return { encrypted: cipherName !== 'none' };
    const kdfName = decoder.decode(kdfField.value);
    const kdfOptsField = readWireString(buf, kdfField.next);
    if (!kdfOptsField) {
      return { encrypted: cipherName !== 'none' || kdfName !== 'none' };
    }
    const encrypted = cipherName !== 'none' || kdfName !== 'none';
    if (kdfOptsField.next + 4 > buf.length) return { encrypted };
    const numKeys =
      ((buf[kdfOptsField.next] << 24) >>> 0) |
      (buf[kdfOptsField.next + 1] << 16) |
      (buf[kdfOptsField.next + 2] << 8) |
      buf[kdfOptsField.next + 3];
    if (numKeys >= 1) {
      const pubBlobField = readWireString(buf, kdfOptsField.next + 4);
      if (pubBlobField) {
        const typeField = readWireString(pubBlobField.value, 0);
        if (typeField) {
          const keyTypeHint = mapSSHKeyTypeLabel(decoder.decode(typeField.value));
          return { encrypted, keyTypeHint };
        }
      }
    }
    return { encrypted };
  } catch {
    return { encrypted: false };
  }
}

async function readTextChecked(file: File, maxBytes: number, maxLabel: string): Promise<string> {
  if (file.size > maxBytes) {
    throw new KeyFileValidationError(
      `文件「${file.name}」体积超过限制（最大支持 ${maxLabel}）`,
      'TOO_LARGE'
    );
  }
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0) {
      throw new KeyFileValidationError(
        `文件「${file.name}」为二进制文件，请选择文本格式的 SSH 密钥文件`,
        'BINARY'
      );
    }
  }
  const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  const normalized = normalizeKeyText(text);
  if (!normalized) {
    throw new KeyFileValidationError(`文件「${file.name}」内容为空`, 'EMPTY');
  }
  return normalized;
}

export async function readPrivateKeyFile(file: File): Promise<ParsedPrivateKeyFile> {
  const normalized = await readTextChecked(file, MAX_PRIVATE_KEY_FILE_BYTES, '256 KB');

  if (normalized.startsWith('PuTTY-User-Key-File-')) {
    throw new KeyFileValidationError(
      '暂不支持 PuTTY (.ppk) 格式，请先使用 PuTTYgen 转换为 OpenSSH / PEM 格式私钥后再上传',
      'PUTTY_PPK'
    );
  }
  if (looksLikePublicKeyText(normalized)) {
    throw new KeyFileValidationError(
      `文件「${file.name}」是 SSH 公钥 (.pub)，请上传对应的私钥文件（如 id_ed25519、.pem、.key）`,
      'IS_PUBLIC_KEY'
    );
  }

  const headerMatch = normalized.match(/-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----/);
  if (!headerMatch) {
    throw new KeyFileValidationError(
      `文件「${file.name}」不是有效的 SSH 私钥格式（未识别到 PEM / OpenSSH 私钥头）`,
      'INVALID_FORMAT'
    );
  }

  const blockType = headerMatch[1];
  let formatLabel = 'PEM 私钥';
  let keyTypeHint: string | undefined;
  let encrypted = false;

  if (blockType === 'OPENSSH PRIVATE KEY') {
    formatLabel = 'OpenSSH 私钥';
    const meta = inspectOpenSSHMetadata(normalized);
    encrypted = meta.encrypted;
    keyTypeHint = meta.keyTypeHint;
  } else if (blockType === 'RSA PRIVATE KEY') {
    formatLabel = 'PEM 私钥';
    keyTypeHint = 'RSA';
    encrypted = /Proc-Type:\s*4,\s*ENCRYPTED/i.test(normalized) || /DEK-Info:/i.test(normalized);
  } else if (blockType === 'EC PRIVATE KEY') {
    formatLabel = 'PEM 私钥';
    keyTypeHint = 'ECDSA';
    encrypted = /Proc-Type:\s*4,\s*ENCRYPTED/i.test(normalized) || /DEK-Info:/i.test(normalized);
  } else if (blockType === 'DSA PRIVATE KEY') {
    formatLabel = 'PEM 私钥';
    keyTypeHint = 'DSA';
    encrypted = /Proc-Type:\s*4,\s*ENCRYPTED/i.test(normalized) || /DEK-Info:/i.test(normalized);
  } else if (blockType === 'ENCRYPTED PRIVATE KEY') {
    formatLabel = 'PKCS#8 私钥';
    encrypted = true;
  } else if (blockType === 'PRIVATE KEY') {
    formatLabel = 'PKCS#8 私钥';
  }

  return {
    file,
    fileName: file.name,
    fileSize: file.size,
    content: `${normalized}\n`,
    formatLabel,
    keyTypeHint,
    encrypted,
    suggestedName: suggestCredentialName(file.name),
  };
}

export async function readPublicKeyFile(file: File): Promise<ParsedPublicKeyFile> {
  const normalized = await readTextChecked(file, MAX_PUBLIC_KEY_FILE_BYTES, '64 KB');
  const lines = normalized
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length !== 1 || !looksLikePublicKeyText(lines[0])) {
    throw new KeyFileValidationError(
      `文件「${file.name}」不是有效的 OpenSSH 公钥 (.pub) 文件`,
      'INVALID_FORMAT'
    );
  }
  const firstToken = lines[0].split(/\s+/)[0] || '';
  const keyTypeLabel = mapSSHKeyTypeLabel(firstToken) || firstToken;
  return {
    file,
    fileName: file.name,
    fileSize: file.size,
    content: lines[0],
    keyTypeLabel,
  };
}
