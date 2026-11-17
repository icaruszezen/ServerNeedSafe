import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webDir = path.resolve(__dirname, '..');
const repoRoot = path.resolve(webDir, '..');
const publicDir = path.join(webDir, 'public');
const zkDir = path.join(webDir, 'src', 'zk');

fs.mkdirSync(publicDir, { recursive: true });
fs.mkdirSync(zkDir, { recursive: true });

if (
  process.env.SNS_PREBUILT_WASM === '1' &&
  fs.existsSync(path.join(publicDir, 'sns-zk.wasm.gz')) &&
  fs.existsSync(path.join(zkDir, 'wasm_exec.js')) &&
  fs.existsSync(path.join(zkDir, 'wasmIntegrity.json'))
) {
  console.log('[sns-zk-wasm] Using prebuilt zero-knowledge WASM artifacts from wasm-builder stage');
  process.exit(0);
}

const goRoot = execFileSync('go', ['env', 'GOROOT'], { encoding: 'utf8' }).trim();
const wasmExecCandidates = [
  path.join(goRoot, 'lib', 'wasm', 'wasm_exec.js'),
  path.join(goRoot, 'misc', 'wasm', 'wasm_exec.js'),
];
const wasmExecSrc = wasmExecCandidates.find((p) => fs.existsSync(p));
if (!wasmExecSrc) {
  throw new Error(`Could not locate Go wasm_exec.js under GOROOT=${goRoot}`);
}
fs.copyFileSync(wasmExecSrc, path.join(zkDir, 'wasm_exec.js'));

const tmpWasm = path.join(os.tmpdir(), `sns-zk-${process.pid}-${Date.now()}.wasm`);
try {
  execFileSync(
    'go',
    ['build', '-trimpath', '-ldflags=-s -w', '-o', tmpWasm, './cmd/wasm'],
    {
      cwd: repoRoot,
      env: { ...process.env, GOOS: 'js', GOARCH: 'wasm', CGO_ENABLED: '0' },
      stdio: 'inherit',
    }
  );

  const rawWasm = fs.readFileSync(tmpWasm);
  const sha256 = createHash('sha256').update(rawWasm).digest('hex');
  const gzWasm = zlib.gzipSync(rawWasm, { level: 9 });

  fs.writeFileSync(path.join(publicDir, 'sns-zk.wasm.gz'), gzWasm);
  fs.writeFileSync(
    path.join(zkDir, 'wasmIntegrity.json'),
    JSON.stringify(
      {
        sha256,
        rawBytes: rawWasm.byteLength,
        gzipBytes: gzWasm.byteLength,
      },
      null,
      2
    ) + '\n'
  );

  console.log(
    `[sns-zk-wasm] Built zero-knowledge WASM engine: raw=${(rawWasm.byteLength / 1048576).toFixed(2)} MiB, gzip=${(gzWasm.byteLength / 1048576).toFixed(2)} MiB, sha256=${sha256.slice(0, 16)}...`
  );
} finally {
  if (fs.existsSync(tmpWasm)) {
    fs.unlinkSync(tmpWasm);
  }
}
