# ServerNeedSafe

**面向 Vibe Coding 时代的多服务器安全管理与零知识全量加密 SSH 终端系统**

随着快速迭代开发时代的到来，多云与混合内网服务器暴露面持续扩大。`ServerNeedSafe` 旨在打造一套安全优先的多服务器运维基座，支持 **Docker 服务端网页部署** 与 **Windows 纯本地独立桌面应用** 两种形态，从底层实现全量应用数据的零知识认证加密存储。

---

## 核心特性（当前阶段已实现）

### 1. 双模式无缝部署
- **服务器 Docker 部署（Web 应用界面）**：多阶段构建极简非 Root 容器镜像，内置前端静态资源，一条 `docker compose up -d` 命令即可提供完整的 Web 管理控制台。
- **Windows 纯本地桌面应用（直接双击运行）**：基于纯 Go 交叉编译为单一独立无黑框原生 GUI 程序（`ServerNeedSafe-windows-amd64.exe`），内嵌前端、SSH/SFTP 协议栈与加密引擎，仅监听本地回环 `127.0.0.1` 随机端口并启用进程级实例隔离令牌，无需安装任何外部依赖即可离线运行，默认采用便携式 `./data/vault.sns` 存储。

### 2. 强制管理员密码验证与内存自动擦除
- 首次启动强制引导创建管理员主密码（至少 8 位）。
- 每次启动 Windows 桌面应用或新开浏览器进入 Web 端时，**必须通过管理员密码密码学校验**才可进入系统。
- 内置连续输错密码指数退避防爆破锁定保护、无操作空闲自动锁定、`Ctrl + Shift + L` 一键紧急锁定，锁定时立即清零内存中的主密钥（`DEK`）并断开所有活跃 SSH 会话。

### 3. 零知识全量数据加密存储（抗数据包泄露）
所有服务器配置（IP、端口、账号、备注、分组）、SSH 密码、SSH 私钥与口令、可复用凭据库、信任的主机公钥指纹（`KnownHosts`）、快捷指令、系统设置与安全审计日志**100% 封装在单一认证加密容器 `vault.sns` 中**：
- **密钥派生（KDF）**：`Argon2id`（默认 `64 MiB` 内存硬成本，`time=3`，`threads=4`，32 字节 CSPRNG 随机盐），磁盘不保存任何密码哈希或明文主密钥。
- **信封加密（Envelope Encryption）**：使用 `Argon2id` 派生的 `KEK` 通过 `AES-256-GCM` 封装 256 位随机数据主密钥 `DEK`，支持在不暴露明文落盘的前提下安全轮换管理员密码与主密钥。
- **全量载荷认证加密**：业务状态经压缩并按 `4 KiB` 随机字节块对齐填充（消除精确文件大小侧信道）后，使用 `XChaCha20-Poly1305`（每次写入生成全新 24 字节随机 Nonce）加密，并将文件头作为 `AAD` 绑定认证。
- **安全保证**：即使整个 `data/` 目录或导出的 `.sns` 备份包被攻击者窃取，在不知道管理员密码的情况下无法查看任何一台服务器的 IP、用户名或密钥信息；任何单比特篡改均会被 AEAD 校验直接拦截。

### 4. 完备的多服务器 SSH 与 SFTP 管理
- **主机资产与分组管理**：支持分组筛选、星标置顶、多维搜索、连通性延迟探测与无 Agent 实时指标采集（系统版本、CPU 负载、内存、磁盘）。
- **多种认证与多级跳板机（ProxyJump）**：支持密码认证（兼容 `keyboard-interactive`）、独立 PEM/OpenSSH 私钥（含口令）、引用保险库凭据，以及通过任意受管堡垒机/跳板机建立多级加密隧道直达内网节点。
- **SSH 主机指纹核验（防中间人攻击）**：支持 TOFU 首次信任固定或严格手动确认策略；一旦远程服务器公钥指纹发生变更，立即阻断连接并弹出高危中间人告警。
- **多标签 Web 终端工作台**：基于 `@xterm/xterm` 的多标签并发 PTY 终端，支持窗口自适应缩放、全文检索、实时负载状态栏、快捷指令一键注入。
- **可视化 SFTP 文件管理与在线编辑**：支持目录浏览、流式上传/下载、新建目录/文件、重命名、`chmod` 八进制权限修改及远程配置文件（如 `sshd_config`、`nginx.conf`）在线安全编辑。
- **内置密钥生成器与公钥一键下发**：支持在内存中生成高强度 `Ed25519` 或 `RSA-4096` 密钥对直接存入加密保险库，并一键安全部署公钥至目标服务器 `~/.ssh/authorized_keys`。
- **快捷指令与多机并发执行**：内置安全巡检指令模板，支持跨多台选定服务器并发执行命令并汇总退出码与输出。

---

## 部署与运行指南

### 方式一：服务器 Docker 部署（Web 界面）

```bash
git clone https://github.com/icaruszezen/ServerNeedSafe.git
cd ServerNeedSafe

# 构建并后台启动容器（默认映射 8080 端口，加密数据持久化在 ./data/vault.sns）
docker compose up -d --build
```

启动后使用浏览器访问 `http://<服务器IP>:8080`，首次进入设置管理员密码即可使用。可通过环境变量自定义端口：

```bash
SNS_PORT=9443 docker compose up -d
```

### 方式二：Windows 纯本地应用程序（直接运行）

1. **直接运行编译产物**：
   下载或编译得到单文件程序 `ServerNeedSafe-windows-amd64.exe`（x64）或 `ServerNeedSafe-windows-arm64.exe`（ARM64），复制到任意目录直接双击运行即可打开原生桌面窗口。
   - 程序默认在同级目录自动创建 `data\vault.sns` 存储全量加密数据（便携模式，整个文件夹拷走即可迁移）；若放置在只读目录（如 `C:\Program Files`），则自动回退至 `%LOCALAPPDATA%\ServerNeedSafe\data\vault.sns`。

2. **从源码自行编译（支持在 Linux / macOS / Windows 下编译）**：

   - **Linux / macOS 一键交叉编译全平台产物**：
     ```bash
     bash ./scripts/build-all.sh
     ```
     产物输出至 `dist/` 目录：
     - `dist/ServerNeedSafe-windows-amd64.exe`（Windows 10/11 64 位纯本地桌面端）
     - `dist/ServerNeedSafe-windows-arm64.exe`（Windows ARM64 纯本地桌面端）
     - `dist/sns-server-linux-amd64`（Linux 独立 Web 服务端单文件）

   - **Windows PowerShell 本地编译**：
     ```powershell
     .\scripts\build-windows.ps1
     ```

---

## 目录架构与后续演进规划

```text
ServerNeedSafe/
├── cmd/
│   ├── server/          # Docker / Linux Web 服务端入口
│   └── desktop/         # Windows 纯本地原生桌面 GUI 应用入口 (WebView2 + 回环隔离)
├── internal/
│   ├── vault/           # Argon2id + AES-256-GCM + XChaCha20-Poly1305 零知识加密存储引擎
│   ├── auth/            # 会话认证、防爆破限流、单次票据与本地桌面隔离守卫
│   ├── sshmanager/      # SSH 拨号、跳板机隧道、PTY 终端桥接、SFTP、密钥生成与并发探测
│   └── api/             # REST + WebSocket 路由与内嵌静态前端服务
├── web/                 # React + TypeScript + Vanilla CSS + Xterm.js 现代前端界面
├── Dockerfile           # 多阶段非 Root 容器构建文件
└── docker-compose.yml   # 一键容器编排配置
```

**后续开发规划（模块化预留）**：
- 接入大语言模型（LLM）辅助服务器安全诊断与自然语言运维
- 自动同步最新 CVE 安全漏洞情报库并与受管服务器版本比对
- 一键快速安全补丁修复与回滚编排
- 定时后台巡检服务器异常进程、异常网络连接与登录告警

---

## 安全测试验证

运行完整加密防泄漏、篡改检测、跳板机隧道、MITM 主机指纹拦截与会话鉴权测试套件：

```bash
go test ./internal/... -v -race
```
