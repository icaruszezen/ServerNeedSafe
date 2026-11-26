# ServerNeedSafe

[![CI & Auto Build (Docker + Windows App)](https://github.com/icaruszezen/ServerNeedSafe/actions/workflows/build-release.yml/badge.svg)](https://github.com/icaruszezen/ServerNeedSafe/actions/workflows/build-release.yml)

**面向 Vibe Coding 时代的 7×24 全天候多服务器安全管理、状态监控与 AI 智能运维平台**

`ServerNeedSafe` 提供极速响应的 **7×24 原生 Go 后台守护引擎 + 轻量 Web 管理台** 架构，同时支持 **Docker 服务端网页部署** 与 **Windows 纯本地独立桌面应用** 两种形态：
- **配置加密与运行数据彻底解耦**：仅对凭据、SSH 私钥/密码、API Key、Webhook 等核心敏感配置使用 `XChaCha20-Poly1305` 加密写入 `secrets.enc`；高频监控时序、告警、AI 会话与巡检记录独立异步落盘至纯 JSON 运行态文件，监控、巡检与后台任务完全零锁阻塞、零重加密开销。
- **7×24 永不锁死的后台守护**：静态数据主密钥（`master.key` / `SNS_MASTER_KEY`）与 Web 管理员登录口令完全解耦。进程/容器重启即刻自动就绪，浏览器退出登录、会话超时或在线修改管理员密码均**绝不中断**后台监控采集与 AI 定时巡检。
- **清爽低摩擦的内网/受控主机体验**：Web 管理台默认保持 **7 天（168h）** `HttpOnly; SameSite=Lax` 登录会话且默认关闭空闲踢出（可按需开启），原生兼容常见反向代理与内网直连。

> [!TIP]
> **部署环境建议**：本项目设计面向**内网机器、VPN/WireGuard 私有网络或已做好 HTTPS/防火墙加固的受控公网宿主机**。项目优先保障 7×24 运维监控稳定性、单文件跨平台便携性（`CGO_ENABLED=0`）与静态凭据保护，而非面向不可信多租户宿主机对抗。

---

## 核心加密与分层存储架构

| 层次 | 存储文件 / 机制 | 说明 |
| :--- | :--- | :--- |
| **敏感配置与凭据密文层** | `/data/secrets.enc` (`XChaCha20-Poly1305` + gzip) | 仅存储主机连接信息、SSH 密码/私钥、凭据库、AI Provider API Key、告警/巡检 Webhook、系统设置与管理员登录哈希；仅在配置变更时原子重写，高频监控采集与巡检绝不触发加密落盘 |
| **独立数据加密主密钥** | `/data/master.key` (`0600`) 或环境变量 `SNS_MASTER_KEY` | 首次启动自动生成 256-bit 随机主密钥（支持随时通过环境变量注入外部密钥并自动无缝迁移重封装）。进程/容器重启 `<1ms` 自动就绪，**修改管理员密码永不轮换主密钥、永不暂停后台任务** |
| **高频运行态独立分片** | `monitor_runtime.json` / `aiops_runtime.json` / `audit_logs.json` | 监控快照、时序历史、告警与端口基线、节点延迟/OS 元信息、AI 会话/HostMemory/Runbook/巡检记录、审计日志与敏感配置分锁隔离，通过后台 `2s` 防抖异步原子落盘，进程退出时自动同步刷盘 |
| **轻量登录门禁与便携备份** | 固定轻量 `Argon2id` (`16 MiB`) + `.sns` v3 备份 | 管理员密码仅用于 Web 登录鉴权（保留 5 次输错防爆破冷却）；支持导出用户自定义备份密码加密的 `.sns` 便携备份（可选是否附带运行态数据）及一键跨端认证同步（默认仅同步核心配置与 AI 记忆，不覆盖对端 7×24 监控历史） |

> **老版本无缝升级**：若 `/data` 目录存在旧版 `vault.sns` + `.vault.key`，新版本启动时自动无人值守完成迁移拆分（原密码无缝保留，旧文件归档为 `vault.sns.migrated.bak`）；若仅存在旧版 `vault.sns`，首次输入原管理员密码登录即自动完成一次性永久迁移。

---

## 核心功能特性

1. **双模式无缝部署 + 跨端认证同步**
   - **Docker / Linux Web 服务端**：极简非 Root 容器镜像，挂载 `/data` 即可提供 7×24 守护监控、Web 终端与分层加密存储。
   - **Windows 纯本地独立桌面应用 (`ServerNeedSafe-windows-amd64.exe`)**：单一无黑框原生 GUI 可执行文件，仅绑定 `127.0.0.1` 随机回环端口并启用进程级 Cookie 隔离守卫，完全离线可用；内置**跨实例配置与 AI 知识同步**，默认推送/拉取核心配置与 AI 记忆而保留对端 7×24 监控历史（可选全量同步）。
2. **多服务器资产、多级跳板机 (`ProxyJump`) 与实时探测**
   - 支持分组管理、星标置顶、多维检索、密码/私钥/凭据库三种认证方式，以及通过任意受管堡垒机建立多级 `ProxyJump` 隧道直达内网主机。
3. **多标签 WebSocket 原生终端 + 同屏 SFTP 安全文件管理**
   - 基于 `@xterm/xterm` 与原生二进制 WebSocket PTY 帧的多标签并发终端，支持自适应缩放、全文检索、快捷指令一键注入、TOFU / 严格手动主机公钥指纹核验。
   - 原生流式 SFTP 引擎支持目录浏览、流式上传/下载、新建目录/文件、重命名、`chmod` 权限修改与在线文本编辑。
4. **内置密钥生成器与多机并发巡检**
   - 一键生成 `Ed25519` 或 `RSA-4096` 密钥对并自动部署公钥至目标主机 `~/.ssh/authorized_keys`；支持跨多台主机并发执行批量指令。
5. **7×24 全维无 Agent 服务器状态监控与时序归档**
   - 无需在远端服务器安装任何 Agent，后台原生 Go 巡检引擎通过加密 SSH 通道持续采集 **12 大全方位监控维度**（连通性/系统画像、250ms 双采样真实 CPU 分解、物理内存/Swap/句柄/OOM、全分区容量/Inode/磁盘 IOPS、多网卡速率与 TCP/UDP Socket 状态、Top CPU/RSS 进程、监听端口与公网暴露端口基线、Systemd 服务、Docker 容器及防火墙/SSH 爆破安全态势）。
   - 内置 **18 项多维告警规则**（防抖、自动销警恢复、手动确认与 Webhook 推送），支持一键导出 CSV（含 UTF-8 BOM）/ JSON 历史报表。
6. **AI 智能运维、混合记忆、定时安全巡检与外部 AI 接管 (MCP)**
   - 原生兼容 **OpenAI Chat Completions** 与 **Anthropic Messages** 两大流式 Tool-Calling 协议（内置 DeepSeek、通义千问、Claude、OpenAI、SiliconFlow 及本地 **Ollama** 预设），受管主机 SSH 密码/私钥严格物理隔离、绝不进入大模型上下文。
   - **原生内置 MCP Streamable HTTP 网关 (`/api/mcp`)**：支持 **Claude Code、Codex、Antigravity、Cursor** 等本地 AI 软件通过持久化作用域令牌直接接管 AI 巡检——认领后台异常巡检队列、执行只读白名单 SSH/SFTP 深度取证、回写结构化报告并触发飞书/钉钉/企微 Webhook、增量更新主机画像与记忆；支持「内置模型 / 纯外部 AI 接管 / 外部优先+超时回退内置」三模式切换，以及受控变更提案（强制落入 Web 端 HITL Diff 审批队列，绝不盲目自动执行）；Windows 桌面版默认保持强隔离，支持按需开启 `127.0.0.1:18900` 独立 MCP 回环端口。
   - 支持 **独立 AI 诊断中心 + SSH 终端同屏副驾驶**、`参谋 / 标准受控 / 自治执行` 三级审批（含 Git Unified Diff 对比卡片）、`HostMemory` 主机画像记忆、`Runbook` 技能沉淀，以及异常按需唤醒大模型并推送至飞书/钉钉/企业微信/HMAC Webhook 的 7×24 后台定时巡检。

---

## 部署与运行指南

### 方式一：服务器 Docker 部署（7×24 守护服务端）

```bash
docker run -d \
  --name serverneedsafe \
  --restart unless-stopped \
  -p 127.0.0.1:18899:8080 \
  -v $(pwd)/data:/data \
  ghcr.io/icaruszezen/serverneedsafe:latest
```

或使用 Docker Compose 从源码构建启动（默认仅监听宿主机回环 `127.0.0.1:18899`）：

```bash
git clone https://github.com/icaruszezen/ServerNeedSafe.git
cd ServerNeedSafe
mkdir -p data && chown -R 10001:10001 data
docker compose up -d --build
```

> **反向代理与外部主密钥建议**：推荐在内网或反向代理（Nginx/Caddy 开启 HTTPS 与 `/api/ws/` WebSocket 转发，参考 [`deploy/nginx-reverse-proxy.conf.example`](deploy/nginx-reverse-proxy.conf.example)）后运行。如需将主密钥与 `/data` 目录分离存放，可注入环境变量 `SNS_MASTER_KEY=<≥32字节随机密钥>`；通过 `SNS_SESSION_TTL` 可自定义登录有效期（默认 `168h` 即 7 天）。

### 方式二：Windows 纯本地桌面应用（直接双击运行）

1. 前往本仓库 **GitHub Releases** 或 **Actions Artifacts (`ServerNeedSafe-Windows-App`)** 下载 `ServerNeedSafe-windows-amd64.exe`（或 `arm64` 版本）直接双击运行。
2. 从源码一键交叉编译全平台产物（Linux / macOS）：
   ```bash
   bash ./scripts/build-all.sh
   ```
   输出产物位于 `dist/`：
   - `dist/ServerNeedSafe-windows-amd64.exe` / `dist/ServerNeedSafe-windows-arm64.exe`
   - `dist/sns-server-linux-amd64` / `dist/sns-server-linux-arm64`
   - `dist/SHA256SUMS.txt`

---

## 目录架构

```text
ServerNeedSafe/
├── cmd/
│   ├── server/          # 7×24 守护 Web 服务端入口（自动加载 secrets.enc、监控与 AI 巡检）
│   └── desktop/         # Windows 纯本地原生桌面 GUI 应用入口 (WebView2 + 回环进程守卫)
├── internal/
│   ├── vault/           # 分层存储引擎：secrets.enc (XChaCha20-Poly1305) + 独立异步防抖运行态 JSON + 便携备份/老版迁移
│   ├── auth/            # 7 天默认 HttpOnly 会话管理、防爆破冷却与桌面回环守卫
│   ├── sshmanager/      # 原生 SSHv2 拨号、ProxyJump、PTY 终端、流式 SFTP 与密钥生成
│   ├── monitor/         # 7×24 无 Agent 全维状态采集、定时巡检调度、18 项告警与报表导出
│   ├── aiops/           # AI 运维 ReAct 引擎、风险分类器、Unified Diff、混合记忆与巡检推送
│   └── api/             # REST + SSE + 二进制 WebSocket PTY 路由、跨端同步与集成测试套件
└── web/                 # 轻量 React + TypeScript + Xterm + SVG 时序图表前端
```

---

## 构建与集成测试

```bash
cd web && npm ci && npm run build && cd ..
go vet ./...
go test ./... -v -race -count=1
```
