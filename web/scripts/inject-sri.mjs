import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const distDir = path.resolve(__dirname, '..', 'dist');
const indexPath = path.join(distDir, 'index.html');

if (!fs.existsSync(indexPath)) {
  throw new Error(`Missing ${indexPath}`);
}

let html = fs.readFileSync(indexPath, 'utf8');

function sriForAsset(assetHref) {
  const cleanRel = assetHref.replace(/^\//, '');
  const fullPath = path.join(distDir, cleanRel);
  if (!fs.existsSync(fullPath)) return null;
  const bytes = fs.readFileSync(fullPath);
  return 'sha384-' + createHash('sha384').update(bytes).digest('base64');
}

html = html.replace(/<(script|link)\b([^>]*?)>/gi, (fullTag, tagName, attrs) => {
  if (/\bintegrity\s*=/.test(attrs)) return fullTag;
  const attrMatch = attrs.match(/\b(?:src|href)\s*=\s*"(\/assets\/[^"]+)"/i);
  if (!attrMatch) return fullTag;
  const integrity = sriForAsset(attrMatch[1]);
  if (!integrity) return fullTag;
  const trimmed = attrs.replace(/\/\s*$/, '');
  const selfClosing = /\/\s*$/.test(attrs) ? ' /' : '';
  return `<${tagName}${trimmed} integrity="${integrity}"${selfClosing}>`;
});

fs.writeFileSync(indexPath, html);
console.log('[sns-sri] Injected SHA-384 Subresource Integrity hashes into dist/index.html');
