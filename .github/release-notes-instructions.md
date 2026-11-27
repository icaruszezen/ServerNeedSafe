# ServerNeedSafe Release Notes Style Guide

When generating bilingual release notes for **ServerNeedSafe**, follow these conventions:

## Language & Tone
- **Simplified Chinese (`notes_zh`)**: Clear, concise, accurate engineering Chinese targeted at DevOps/SRE users and self-hosted server administrators. Keep technical terms (SSH, SFTP, ProxyJump, MCP, SSE, Docker, GHCR, SHA-256, WebView2, XChaCha20-Poly1305) in standard English.
- **English (`notes_en`)**: Idiomatic, concise technical English — write natural English release notes that mirror the exact same changes and structure as the Chinese section (not word-for-word machine translation).

## Grouping & Structure
Organize changes into 1–4 thematic `###` headings relevant to the actual changes in the release (omit empty categories), for example:
- `### ✨ 新功能与核心增强` / `### ✨ New Features & Highlights`
- `### 🔒 安全与权限加固` / `### 🔒 Security & Hardening`
- `### 🐛 问题修复与稳定性提升` / `### 🐛 Bug Fixes & Reliability`
- `### ⚙️ 工程构建与运维体验` / `### ⚙️ Build, CI/CD & Developer Experience`

## Guidelines
- Focus on **user-visible impact**, behavior changes, fixed bugs, and operational/security improvements rather than restating raw filenames or internal variable names unless helpful.
- Group closely related commits/PRs cleanly, and always reference the corresponding PR number at the end of relevant bullet items (e.g., `(#13)`).
- Exclude trivial merge commits or automated version bump commits (`chore(release): ...`).
- Do **not** include the top-level version heading (`## vX.Y.Z`) or `Full Changelog` link inside `notes_zh` / `notes_en` — the release script renders those automatically.
