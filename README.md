# ServerNeedSafe

[![CI & Auto Build (Docker + Windows App)](https://github.com/icaruszezen/ServerNeedSafe/actions/workflows/build-release.yml/badge.svg)](https://github.com/icaruszezen/ServerNeedSafe/actions/workflows/build-release.yml)

**面向 Vibe Coding 时代的多服务器安全管理与客户端零知识端到端加密 (E2EE) SSH 终端系统**

随着快速迭代开发时代的到来，多云与混合内网服务器暴露面持续扩大。`ServerNeedSafe` 旨在打造一套**抗部署服务器 `root` 泄露**的多服务器运维安全基座，同时支持 **Docker 服务端网页部署** 与 **Windows 纯本地独立桌面应用** 两种形态：**在不知道管理员密码的前提下，即使部署本应用的服务器 `root` 权限完全沦陷（包括磁盘窃取、进程内存 `gcore` 转储、网卡 `tcpdump` 抓包），攻击者也无法获取任何一台受管服务器的配置、密钥或终端/SFTP 数据**。

---

## 零知识抗服务器 Root 泄露威胁模型与密码学架构

| 攻击者掌握的服务器 `root` 能力 | 传统服务端加密架构风险 | ServerNeedSafe v2 客户端零知识架构防护结果 |
| :--- | :--- | :--- |
| **窃取 `/data/vault.sns` 磁盘文件** | 离线撞库弱口令或读取未加密元数据 | `SNSVAULT v2` 容器采用 `Argon2id (64 MiB, t=3, p=4)` + `XChaCha20-Poly1305` + `4 KiB` 随机块对齐填充，**零明文、零大小侧信道** |
| **服务器 `root` 实时 Dump 进程内存 (`/proc/<pid>/mem`)** | 解锁期间服务端内存驻留主密钥 `DEK` 与解密后的主机私钥 | **服务端物理不持有任何解密代码、密码或 `DEK`**（`sns-server` 甚至不导入 `ClientVault` 或 `sshmanager`），内存中仅有盲密文与公开 `Ed25519` 公钥 |
| **服务器 `root` 抓包 HTTP / WebSocket 流量** | 捕获登录请求中的明文密码、API 返回的服务器列表与 WebSocket 终端明文 | 管理员密码**永不离开客户端**（通过 `Ed25519` 零知识随机挑战签名登录）；SSHv2 与 SFTP 握手在浏览器独立 **Web Worker WASM** 中端到端完成，服务端仅盲转发已加密的 SSH 二进制帧 |
| **篡改或回滚服务器磁盘密文 / 降级 KDF 参数** | 诱导客户端使用弱 KDF 派生密钥或回退至旧配置 | 客户端强制校验 `KDF ≥ 16 MiB` 下限、`HTML SHA-384 SRI` + `WASM SHA-256` 自校验，并在本地持久化 `VaultAnchor` 追踪单调递增 `Revision #` 拦截任何回滚、抹除或替换攻击 |

### 核心密码学流水线 (`SNSVAULT v2`)
1. **双域隔离密钥派生**：在客户端独立 Web Worker 的 Go WASM 线性内存中，由管理员密码经 `Argon2id (64 MiB)` 生成主种子，再通过 `HKDF-SHA256` 严格域分离派生：
   - `KEK`（`sns-v2-vault-kek`）：通过 `AES-256-GCM` 封装随机 256 位数据加密主密钥 `DEK`。
   - `Ed25519` 认证密钥对（`sns-v2-auth-ed25519`）：公钥随容器头部公开，私钥仅在客户端内存对服务端单次随机挑战（`ChallengeID + Nonce + VaultID`）与每次密文提交（`Revision + SHA256(Blob)`）进行数字签名。
2. **全量 AEAD 认证加密**：所有服务器名称、IP、端口、用户名、SSH 密码、PEM/OpenSSH 私钥、口令、分组、快捷指令、`KnownHosts` 主机指纹、偏好设置与安全审计日志压缩并随机填充对齐 `4 KiB` 后，使用 `XChaCha20-Poly1305` 全量加密，并将完整头部（含 `VaultID`、单调递增 `Revision`、KDF 参数、`AuthPublicKey`）绑定为 `AAD`。
3. **锁定时物理销毁内存**：点击「立即锁定」、空闲超时或按下 `Ctrl + Shift + L` 时，客户端立即调用 `worker.terminate()` 彻底卸载销毁整个 Web Worker 与 WASM 线性内存空间，同步吊销服务端会话并切断所有盲 TCP 隧道。

---

## 核心功能特性

1. **双模式无缝部署 + 跨端零知识云同步**
   - **Docker / Linux Web 服务端**：多阶段极简非 Root 容器镜像，仅需挂载 `/data` 即可提供盲密文存储与加密流量中继。
   - **Windows 纯本地独立桌面应用 (`ServerNeedSafe-windows-amd64.exe`)**：单一无黑框原生 GUI 可执行文件，仅绑定 `127.0.0.1` 随机回环端口并启用进程级 Cookie 隔离守卫，完全离线可用；内置**跨端零知识密文云同步**，可随时将本地密文安全推送/拉取至远端 `sns-server`。
2. **多服务器资产、多级跳板机 (`ProxyJump`) 与实时探测**
   - 支持分组管理、星标置顶、多维检索、密码/私钥/凭据库三种认证方式。
   - 支持通过任意受管堡垒机建立客户端端到端多级 `direct-tcpip` 隧道直达内网主机（连内网目标主机地址都包裹在外层 SSH 加密隧道内，部署服务器 `root` 甚至无法获知第二跳内网 IP）。
3. **多标签 Web 终端工作台 + 同屏 SFTP 安全文件管理**
   - 基于 `@xterm/xterm` 的多标签并发 PTY 终端，支持自适应缩放、全文检索、快捷指令一键注入、TOFU / 严格手动主机公钥指纹防中间人核验。
   - 客户端 WASM 原生 SFTP 引擎支持目录浏览、流式上传/下载、新建目录/文件、重命名、`chmod` 权限修改与在线文本编辑，文件路径与内容全程端到端加密。
4. **内置密钥生成器与多机并发巡检**
   - 在客户端 WASM 内存中直接生成 `Ed25519` 或 `RSA-4096` 密钥对并一键部署公钥至目标主机 `~/.ssh/authorized_keys`；支持跨多台主机并发执行巡检指令。
5. **全维服务器状态监控与端到端零知识时序归档（无 Agent 定时巡检）**
   - 在客户端 WASM 隔离沙箱内内置后台定时 SSH 巡检调度器与时序引擎，无需在远端服务器安装任何 Agent，全程通过盲 TCP 中继建立端到端 SSH 加密通道完成采集，**部署服务器 `root` 全程零明文可见**：
   - **12 大全方位监控采集维度**：连通性与系统画像（RTT 延迟、OS/内核/CPU/虚拟化/Uptime/NTP/温度）、250ms 双采样真实 CPU 分解（`User / System / IOWait / Steal`）与归一化负载、物理内存/Swap/文件句柄（`file-nr`）/OOM Kill、全分区容量/Inode 与块设备读写速率/IOPS、多网卡上下行速率/错丢包与内核 TCP/UDP Socket 状态矩阵、进程状态分布与 Top CPU/RSS 排行、监听端口审计与公网暴露端口安全基线、Systemd 故障服务与自定义必监服务、Docker 容器健康、以及主机防火墙/SELinux/特权账号/在线终端/SSH 爆破源 IP 安全态势。
   - **18 项多维告警规则与防抖自愈**：内置主机离线、CPU/IOWait/负载、内存/Swap/OOM/FD、磁盘空间/Inode、SSH 高延迟、僵尸进程、CLOSE_WAIT 泄漏、Systemd/必监服务故障、Docker 异常容器、新公网暴露端口漂移、必监端口掉线及 SSH 爆破攻击等 18 条可配置规则，支持连续超限次数防抖、自动销警恢复、手动确认与 Webhook 推送。
   - **100% 客户端零知识加密持久化与报表导出**：所有监控配置、最新快照、环形缓冲历史时序曲线、告警记录与端口基线均在客户端经 `XChaCha20-Poly1305` 封装进 `SNSVAULT v2` 密文容器，锁库时随 Web Worker 立即物理销毁并暂停巡检；支持纯客户端零知识导出 CSV（含 UTF-8 BOM）/ JSON 历史报表。
6. **纯客户端零知识 AI 智能运维、混合记忆与定时安全巡检（零 Python / 零服务端明文）**
   - **WASM 隔离沙箱直连大模型（双协议多厂商）**：AI ReAct 引擎完整运行在客户端独立 Web Worker WASM 内，纯 Go 原生兼容 **OpenAI Chat Completions** 与 **Anthropic Messages** 两大流式 Tool-Calling 协议，内置 DeepSeek、阿里云百炼（通义千问）、Anthropic Claude、OpenAI、SiliconFlow 及本地离线 **Ollama** 一键预设；大模型 API Key 与 Webhook 密钥随保险库零知识加密，且受管主机 SSH 密码/私钥严格物理隔离、绝不进入大模型上下文。
   - **独立 AI 诊断中心 + SSH 终端同屏副驾驶**：既可在独立中心跨多台主机进行流式安全体检与排障，也可在 Xterm 终端右侧一键唤出副驾驶，自动感知端到端终端最近输出报错并将修复命令一键注入当前 PTY。
   - **三级受控执行（HITL）与 Git Unified Diff 审批**：支持 `参谋模式`、`标准受控`（默认：只读探针自动采集，服务重启与远程配置文件修改自动生成 Git Unified Diff 对比卡片等待管理员一键批准）与 `自治执行`（底层硬拦截 `rm -rf /`、`mkfs`、`dd` 等毁灭性命令）。
   - **主机环境画像记忆与 Runbook 技能沉淀**：AI 在排障中自动增量归档每台服务器的系统架构、核心服务与部署路径（`HostMemory`），并在复杂故障解决后提炼标准化 `Runbook` 草案，一键加密保存并可同步至快捷指令。
   - **后台定时巡检与多通道告警推送**：低开销只读探针周期检测 CPU/内存/磁盘阈值、监听端口基线突变、1 小时内 SSH 暴力破解激增与非 root `UID=0` 特权账号；仅当发现异常时按需唤醒大模型生成根因报告，并推送至飞书、钉钉、企业微信或自定义 HMAC 签名 Webhook；支持「锁定界面（保持后台监控与巡检）」与「彻底销毁内存封存」双级锁控。

---

## 部署与运行指南

### 方式一：服务器 Docker 部署（零知识 Web 服务端）

```bash
docker run -d \
  --name serverneedsafe \
  --restart unless-stopped \
  -p 8080:8080 \
  -v $(pwd)/data:/data \
  ghcr.io/icaruszezen/serverneedsafe:latest
```

或使用 Docker Compose 从源码构建启动：

```bash
git clone https://github.com/icaruszezen/ServerNeedSafe.git
cd ServerNeedSafe
docker compose up -d --build
```

> **安全建议**：公网部署时建议配合反向代理开启 HTTPS（TLS），结合内置的 HTML `SHA-384 SRI` 与 Worker `WASM SHA-256` 完整性校验，确保首次加载的前端静态代码不被网络链路篡改。

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
│   ├── server/          # 零知识盲存储 + 盲 TCP 中继 Web 服务端入口（零明文、零密钥）
│   ├── desktop/         # Windows 纯本地原生桌面 GUI 应用入口 (WebView2 + 回环守卫)
│   └── wasm/            # 浏览器独立 Web Worker 零知识密码学、监控、AI 运维与 SSH/SFTP WASM 入口
├── internal/
│   ├── vault/           # SNSVAULT v2 容器 (Argon2id + HKDF + XChaCha20-Poly1305 + 监控与 AI 记忆加密归档)
│   ├── auth/            # Ed25519 单次随机挑战会话、指数退避防爆破与单次中继票据
│   ├── relay/           # 零元数据保留的 WebSocket ↔ TCP 盲二进制流中继器
│   ├── sshmanager/      # 纯客户端端到端 SSHv2 拨号、ProxyJump、PTY 终端、SFTP 与密钥生成
│   ├── monitor/         # 客户端无 Agent 全维状态采集脚本、解析器、定时巡检调度、18 项告警与报表导出
│   ├── aiops/           # 客户端零知识 AI 运维 ReAct 引擎、风险分类器、Unified Diff、混合记忆与巡检推送
│   ├── zkclient/        # 跨原生与 WASM 的零知识客户端引擎、CAS 自动合并与远端密文云同步
│   └── api/             # 严格拒绝未知字段的零知识 REST/WS 路由与模拟服务器 root 沦陷测试套件
└── web/                 # React + TypeScript + SVG 时序图表 + AI 运维工作台 + Web Worker + SRI 前端
```

---

## 安全测试验证（含模拟服务器 Root 沦陷全链路取证测试）

运行静态分析（含原生与 `js/wasm` 目标）及竞态安全测试套件（含 [`root_breach_test.go`](internal/api/root_breach_test.go) 对磁盘、全量 TCP/WS 抓包字节流、服务端 Go 堆内存结构体的零泄漏断言及主动回滚/篡改/降级/覆盖攻击拦截验证）：

```bash
cd web && npm ci && npm run build && cd ..
go vet ./...
GOOS=js GOARCH=wasm go vet ./cmd/wasm ./internal/vault ./internal/sshmanager ./internal/monitor ./internal/aiops ./internal/zkclient
go test ./... -v -race -count=1
```
