# ServerNeedSafe

[![CI & Auto Build (Docker + Windows App)](https://github.com/icaruszezen/ServerNeedSafe/actions/workflows/build-release.yml/badge.svg)](https://github.com/icaruszezen/ServerNeedSafe/actions/workflows/build-release.yml)

**面向 Vibe Coding 时代的 7×24 全天候多服务器安全管理、状态监控与 AI 智能运维平台**

`ServerNeedSafe` 提供极速响应的 **7×24 原生 Go 后台守护引擎 + 轻量 Web 管理台** 架构，同时支持 **Docker 服务端网页部署** 与 **Windows 纯本地独立桌面应用** 两种形态：
- **首屏 `<50ms` 秒开**：彻底移除浏览器端重型 WASM 运行时，静态资源配合 `SHA-384 SRI` 完整性校验与长效不可变缓存，打开页面即刻进入工作台。
- **7×24 不间断监控与 AI 巡检**：通过 `SNSVAULT v2`（`XChaCha20-Poly1305`）加密容器与受限权限（`0600`）本地封装密钥 `.vault.key` 实现进程/容器重启 `<1ms` 自动挂载，SSH 状态采集与 AI 定时安全巡检全天候在后台守护运行，与浏览器是否打开彻底解耦。
- **独立 Web 管理门禁与可移植加密备份**：未认证请求零元数据暴露；支持 `HttpOnly; SameSite=Strict` 会话 Cookie、8 小时最大有效期与可配空闲超时；导出的 `.sns` 备份文件保持 100% 纯密码封装格式（不含 `.vault.key`），跨机器恢复与远端云同步安全便携。

---

## 核心安全与双轨存储架构 (`SNSVAULT v2` + `.vault.key`)

| 安全机制 | 实现细节 | 运行时效果 |
| :--- | :--- | :--- |
| **`SNSVAULT v2` 落盘全量认证加密** | 所有主机配置、SSH 密码/私钥、口令、`KnownHosts` 指纹、监控快照与 AI 记忆经压缩与 `4 KiB` 随机块对齐填充后，通过 `XChaCha20-Poly1305` 加密写入 `/data/vault.sns`，完整头部绑定为 `AAD` | 磁盘与导出的 `.sns` 备份零明文落盘，篡改任意比特立即被 AEAD 认证拦截 |
| **本地快速启动密钥 (`.vault.key`)** | 首次初始化或老版本首次密码登录时，自动在 `/data/.vault.key`（严格 `0600` 权限，支持通过环境变量 `SNS_MASTER_KEY` 外部注入）以 `AES-256-GCM` 封装 `DEK` | 容器或桌面进程重启后 `<1ms` 自动挂载保险库并恢复 7×24 监控与 AI 巡检；存量老版本 `vault.sns` 首次输入管理员密码后自动无感平滑迁移 |
| **可调档 `Argon2id` 密码派生** | 原生多线程 Go `Argon2id`（默认 `64 MiB / t=3 / p=4`，实测约 `45ms`）+ `HKDF-SHA256` 双域隔离派生 `KEK` 与 `Ed25519` 认证密钥；安全中心内置 `16 / 32 / 64 / 128 MiB` 四档在线切换 | 兼顾服务端/桌面端极速口令核验与导出的 `.sns` 离线备份抗暴力破解强度 |
| **会话与后台任务完全解耦** | `HttpOnly` 会话默认最长 8 小时 + 30 分钟无操作自动锁定；按下 `Ctrl + Shift + L`、点击「退出登录」或「吊销全部会话」仅收回 Web 访问权 | 浏览器关闭或管理台锁定后，后台 7×24 SSH 状态监控与 AI 异常巡检告警不受任何影响 |

---

## 核心功能特性

1. **双模式无缝部署 + 跨端密文云同步**
   - **Docker / Linux Web 服务端**：极简非 Root 容器镜像，挂载 `/data` 即可提供 7×24 守护监控、Web 终端与加密存储。
   - **Windows 纯本地独立桌面应用 (`ServerNeedSafe-windows-amd64.exe`)**：单一无黑框原生 GUI 可执行文件，仅绑定 `127.0.0.1` 随机回环端口并启用进程级 Cookie 隔离守卫，完全离线可用；内置**跨端 `SNSVAULT v2` 签名密文云同步**，可随时将本地加密容器推送/拉取至远端 `sns-server`。
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
6. **AI 智能运维、混合记忆与后台定时安全巡检**
   - 原生兼容 **OpenAI Chat Completions** 与 **Anthropic Messages** 两大流式 Tool-Calling 协议（内置 DeepSeek、通义千问、Claude、OpenAI、SiliconFlow 及本地 **Ollama** 预设），受管主机 SSH 密码/私钥严格物理隔离、绝不进入大模型上下文。
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

> **反向代理与外部主密钥建议**：生产环境推荐容器仅绑定 `127.0.0.1:18899`，外部通过域名 Nginx 开启 HTTPS（TLS）与 `/api/ws/` WebSocket 反向代理访问（完整配置模板见 [`deploy/nginx-reverse-proxy.conf.example`](deploy/nginx-reverse-proxy.conf.example)）。如需将快速启动主密钥与 `/data` 目录分离，可额外注入环境变量 `SNS_MASTER_KEY=<32字节以上随机高熵密钥>`。

> [!WARNING]
> **`.vault.key` 威胁模型说明**
> - **文件模式（未配置 `SNS_MASTER_KEY`，默认）**：封装主密钥与被封装的 `DEK` 同存于 `/data/.vault.key`，仅依赖 `0600` 文件权限保护。**获得整个 `/data` 目录（或宿主机 root）的攻击者可直接解密 `vault.sns`**；导出的 `.sns` 备份不含 `.vault.key`，仍只能凭管理员密码解密。服务端模式启动时会打印安全提示，安全中心接口 `auto_unlock_mode` 字段显示 `file`。
> - **外部主密钥模式（推荐）**：注入 `SNS_MASTER_KEY`（**至少 32 字节**随机值，如 `openssl rand -base64 48`；过短会被拒绝），`.vault.key` 仅含密文，单独泄露 `/data` 无法解密。已启用外部主密钥的 `.vault.key` 在环境变量缺失时**不会被静默降级**为文件模式（需手动删除 `.vault.key` 后重新登录方可降级）。
> - 远端轮换密码或导入其他保险库后，失效的 `.vault.key` 会被自动清除，下次管理员密码登录时重新生成。
>
> **其他加固约束**：会话 Cookie 仅对同源请求生效（反向代理须保留 `Host` 或传递 `X-Forwarded-Host`）；`X-Real-IP` / `X-Forwarded-For` 仅在直连对端为本机/内网反向代理时采信；未认证的服务端 `Argon2id` 口令校验并发上限为 2（繁忙时返回 `429 KDF_BUSY`）；加密容器 KDF 参数上限为 `1 GiB / t=32 / p=64`，超限的备份或远端容器将被拒绝以防内存耗尽。

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
│   ├── server/          # 7×24 守护 Web 服务端入口（自动挂载加密保险库、监控与 AI 巡检）
│   └── desktop/         # Windows 纯本地原生桌面 GUI 应用入口 (WebView2 + 回环进程守卫)
├── internal/
│   ├── vault/           # SNSVAULT v2 加密容器 + ServerKeyManager (.vault.key <1ms 自动解锁与平滑迁移)
│   ├── auth/            # HttpOnly 会话管理（最大 TTL + 空闲超时）、指数退避防爆破与 Ed25519 同步鉴权
│   ├── relay/           # 零元数据保留的 WebSocket ↔ TCP 二进制流中继器
│   ├── sshmanager/      # 原生 SSHv2 拨号、ProxyJump、PTY 终端、流式 SFTP 与密钥生成
│   ├── monitor/         # 7×24 无 Agent 全维状态采集、定时巡检调度、18 项告警与报表导出
│   ├── aiops/           # AI 运维 ReAct 引擎、风险分类器、Unified Diff、混合记忆与巡检推送
│   ├── zkclient/        # 跨实例 SNSVAULT v2 CAS 自动合并与远端密文云同步引擎
│   └── api/             # REST + SSE + 二进制 WebSocket PTY 路由与安全集成测试套件
└── web/                 # 轻量 React + TypeScript + Xterm + SVG 时序图表 + SHA-384 SRI 前端
```

---

## 构建与安全集成测试

```bash
cd web && npm ci && npm run build && cd ..
go vet ./...
go test ./... -v -race -count=1
```
