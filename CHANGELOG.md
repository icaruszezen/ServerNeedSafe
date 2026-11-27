# Changelog

All notable changes to **ServerNeedSafe** are documented in this file.
本文件记录 **ServerNeedSafe** 每个正式版本的中英文更新日志。

## v2.7.0 (2026-11-27)

## 中文更新说明

> 本版本显著降低动态端口与 VPN 网络中的告警误报，并提升告警中心可读性、兼容性与运维排障体验。

### ✨ 新功能与核心增强
- 告警中心新增卡片式三段布局、语义状态条、实测指标焦点卡、处置建议预览与结果汇总栏，并支持一键展开或收起全部修复建议，便于快速分辨告警级别和处置状态 (#18)。
- 端口漂移检测升级为策略版本 3，并可从既有 v2 配置平滑迁移；新增全局及单机级进程豁免、端口豁免、临时 UDP 端口豁免和端口区间规则，支持通配符及 `tcp:`、`udp:` 协议限定 (#19)。
- 新增按端口独立计数的防抖机制，可避免动态端口短时间频繁轮换触发重复告警；告警面板支持一键忽略动态端口进程或端口，并在策略、基线和忽略配置变更时同步更新活跃告警 (#19)。
- 补充全局端口漂移策略接口及告警中心忽略操作入口，使运维人员可以直接管理持续误报源，无需手工修改配置 (#19)。
- README 已全面更新并补充顶部徽章、目录、分层加密与 7×24 架构图、部署模式、环境变量、目录结构及构建测试说明，并提供 Docker、Windows 桌面端和 Linux 二进制部署指引 (#17)。

### 🔒 安全与权限加固
- 端口暴露分类补充 RFC 6598 `100.64.0.0/10` 和 Tailscale IPv6 ULA `fd7a:115c:a1e0::/48`，避免 CGNAT、Tailscale 等私有或覆盖网络地址被误标记为公网监听 (#19)。
- 内置常见动态端口进程与应用豁免，包括 RustDesk、ToDesk、Tailscale、P2P/远程桌面、代理软件及 macOS 动态端口进程，降低误报同时保留真实公网监听告警 (#19)。
- 深色与浅色主题共 44组前景/背景配色均已校验达到 WCAG AA（≥ 4.5:1），包括徽标、辅助文字和状态指示元素 (#18)。

### 🐛 问题修复与稳定性提升
- 修复 RustDesk、ToDesk、syslogd、replicatord 等应用在 UDP `>= 32768` 临时端口间频繁轮换时持续产生端口漂移误报的问题 (#19)。
- 修复 `tailscaled` PeerAPI 动态端口因私网/覆盖网络地址分类错误而触发的漂移告警，并覆盖部分代理与系统瞬态端口场景 (#19)。
- 修复 macOS 15/26 `netstat -anv` 解析偏移：不再将 `rhiwat`、`shiwat` 等窗口尺寸误当作 PID，并提升完整进程名解析准确性 (#19)。
- 修复端口漂移智能建议仅展示前 5 个基线端口、未展示实际漂移端口的问题；建议现在会提供与实际漂移证据相符的排障信息，并按 macOS/Linux 平台返回合适命令 (#19)。
- 修复采集脚本超时路径读取并发缓冲区导致的数据竞争，并限制 Linux 磁盘采集对 `virtiofs`、`9p`、FUSE 等宿主机挂载可能造成的阻塞风险 (#19)。
- 告警界面同步优化深浅主题视觉层级、移动端紧凑指标卡和窄屏堆叠布局；在 768px 及以下保持可用，在 420px 以下避免横向溢出，输入控件尺寸保持不低于 16px (#18)。
- 修复单机忽略进程、忽略端口、策略变更、基线提取及漂移计算各环节的状态同步，并为配置变更实时执行活跃告警和快照一致性处理 (#19)。

### ⚙️ 工程构建与文档体验
- 新增 9 张高清 Retina 运行截图，覆盖监控概览、告警中心、资产路由、终端与 SFTP、AI 智能运维、MCP 网关及安全存储界面，并支持浅色/深色主题适配 (#17)。
- 优化 `.dockerignore` 构建上下文，已忽略文档目录以避免截图资源放大 Docker 镜像构建体积 (#17)。
- 补充端口漂移及 macOS/Linux 采集相关回归测试、告警中心 API 测试和策略迁移测试，前端构建、Go 静态检查、发布脚本测试均已纳入验证范围 (#19)。

---

## English Release Notes

> This release substantially reduces false alarms for dynamic ports and VPN networks while improving alert readability, compatibility, and troubleshooting workflows.

### ✨ New Features & Highlights
- Redesigned Alert Center cards with a clear header, content, and footer structure, semantic status markers, prominent measured values, remediation previews, and result summaries (#18).
- Added one-click controls to expand or collapse all remediation suggestions and to ignore recurring processes or ports directly from the alert workflow (#19).
- Upgraded port-drift policy handling to policy version 3 with seamless migration from v2; global and per-server rules now support ignored processes, ignored ports, ephemeral UDP suppression, wildcard matching, protocol prefixes, and port ranges (#19).
- Added independent debounce counters per drifted port, preventing short-lived dynamic-port rotation from creating duplicate or repeatedly resetting alerts (#19).
- Added global port-drift policy APIs and per-server ignore controls, allowing operators to manage false-positive sources without manual configuration edits (#19).
- Reworked the README with a badge header, table of contents, Mermaid security and 7×24 storage architecture diagrams, deployment modes, environment variables, directory structure, and build/test instructions (#17).

### 🔒 Security & Hardening
- Extended bind exposure classification to recognize RFC 6598 `100.64.0.0/10` and Tailscale IPv6 ULA `fd7a:115c:a1e0::/48`, preventing CGNAT and VPN overlay addresses from being labeled as public IP exposure (#19).
- Added built-in ignore rules for common dynamic-port applications and processes, including RustDesk, ToDesk, Tailscale, P2P and remote-desktop tools, proxy software, and macOS transient services (#19).
- Verified 44 light/dark-theme foreground and background combinations against WCAG AA contrast requirements; every checked pairing meets or exceeds the 4.5:1 ratio (#18).

### 🐛 Bug Fixes & Reliability
- Reduced false port-drift alerts for RustDesk, ToDesk, syslogd, replicatord, and other applications that rapidly rotate UDP ports at or above `32768` (#19).
- Fixed false drift detection for `tailscaled` PeerAPI ports and comparable proxy or system transient ports caused by incorrect private-network exposure classification (#19).
- Fixed macOS 15/26 `netstat -anv` parsing offsets that could interpret window-size fields such as `rhiwat` or `shiwat` as PIDs, improving full process-name resolution (#19).
- Fixed port-drift remediation evidence to report the actual drifted ports instead of only the first five baseline ports, with platform-appropriate diagnostic commands for macOS and Linux (#19).
- Removed a data race in collection timeout paths by avoiding concurrent reads of stdout and stderr buffers, and reduced the risk of hangs on host `virtiofs`, `9p`, and FUSE mounts during disk collection (#19).
- Improved alert contrast and information hierarchy across light and dark themes, with compact metric cards on screens up to 768px and stacked layouts below 420px without horizontal overflow (#18).
- Fixed reconciliation of active alerts and snapshots when server ignore lists, global policies, baseline extraction, or drift calculations change (#19).

### ⚙️ Build, CI/CD & Developer Experience
- Added nine high-resolution Retina screenshots covering monitoring, alerts, assets and routing, terminal/SFTP, AI operations, MCP gateway, and vault security, with light/dark theme support (#17).
- Reduced Docker build-context size by excluding the `docs` directory through `.dockerignore` (#17).
- Expanded regression coverage for port drift, macOS and Linux collection paths, alert-center APIs, and policy migration; frontend builds, Go vet checks, and release-bot tests are included in the validation workflow (#19).

---

### Included Changes / 包含的变更

- #17 docs(readme): 根据最新代码更新 README、优化排版并附带高清运行截图 (@icaruszezen)
- #18 feat(alerts): optimize alert card readability, separation, and contrast (@icaruszezen)
- #19 feat(monitor): optimize port drift detection for dynamic-port apps and VPN overlays (@icaruszezen)

**Full Changelog**: https://github.com/icaruszezen/ServerNeedSafe/compare/v2.6.0...v2.7.0

## v2.6.0 (2026-11-27)

## 中文更新说明

> 本版本新增独立告警中心与智能处置能力，全链路加固 AI 智能运维，并建立自动化双语版本发布流水线。

### ✨ 新功能与核心增强
- 新增独立「告警信息」菜单页，将告警与事件记录从「状态监控」中拆分，并提供活跃告警、确认、处理状态、级别、分类、服务器和关键词等多维筛选，以及「时间流 / 按主机分组」双视图。 (#15)
- 支持在状态监控、集群态势、单机透视、主机资产等页面直接点击告警标志，自动跳转至「告警信息」并定位到对应服务器；工作区启动数据新增各服务器的活跃告警数。 (#15)
- 新增上下文感知智能修复建议引擎，覆盖全部 34 类内置监控告警规则，可结合操作系统、挂载分区、进程、systemd、Docker、端口、SSH 爆破、防火墙等实时主机快照给出根因、证据、排查步骤和处置建议。 (#15)
- 智能建议支持只读命令在终端执行、变更类命令填入终端待确认、复制命令以及端口和安全基线的采纳、复测操作；「AI 深度诊断」可一键携带告警上下文跳转至 AI 智能运维并预填排障提示词。 (#15)
- 新增告警批量确认、人工标记已解决并重置防抖计数、按服务器清理已恢复告警等后端接口与存储能力。 (#15)
- 新增合并 PR 后自动生成双语版本 PR 和一键发布工作流：连续合并的 PR 可增量并入未合并的版本 PR，并自动重新评估 SemVer 和版本说明。 (#14)
- 发布时支持自动打 annotated Tag、创建包含中英文说明的 Draft GitHub Release、调度全平台构建，并清理临时分支和更新发布状态标签。 (#14)
- 新增零依赖 Node.js 发布核心、AI 多引擎适配与发布机器人，支持 Merge、Squash、Rebase 等合并方式，并保留维护者对 PR 描述或 `CHANGELOG.md` 的手动编辑。 (#14)

### 🐛 问题修复与稳定性提升
- 修复新建 AI 运维会话首条消息流式回复不可见、切换会话或主机时流未停止，以及流式 Markdown 和乐观用户消息气泡不完整的问题，并补充停止生成按钮。 (#13)
- 修复移动端网格、缺失的审批操作 Flex 布局、窄屏横向溢出、巡检未读徽章漏计、MCP 状态芯片展示和终端 Copilot 深链跳转等界面问题。 (#13)
- 修复数字输入删除或连续输入时跳变、弹窗 Escape 与键盘访问、IME 组合态误发送，以及已有主机画像切换下拉时误覆盖其他主机的问题。 (#13)
- 修复 AI 运维流式协议和模型兼容性：规范化 SSE 换行与尾部缓冲、解析 OpenAI / Anthropic 内联错误事件、合并连续同角色 Anthropic 消息，并避免跨轮次 ToolCall ID 冲突。 (#13)
- 修复外部 AI MCP 网关、巡检调度、主机长期记忆、Webhook、审批及后台任务的并发、状态同步和边界行为，并在达到最大 ReAct 迭代次数时返回明确总结。 (#13)
- 修复 MCP 令牌创建、启停、删除后的状态同步与错误提示，并补强 AI 运维中心、终端 Copilot 与相关弹窗的交互一致性。 (#13)

### 🔒 安全与权限加固
- 智能修复建议对动态参数实施严格白名单校验和 Shell 转义，防止告警快照中的异常内容造成命令注入；同时区分只读排查与状态变更操作。 (#15)
- 加固外部 AI MCP、HITL 审批、巡检和后台任务的并发与安全边界，补充模型流式异常、无效状态和审批失效后的处理。 (#13)
- 发布自动化中隔离并限制 Copilot CLI 环境变量，优先使用 GitHub 原生 Copilot CLI，并限制 AI 返回结果通过护栏校验后才影响版本号和说明。 (#14)

### ⚙️ 工程构建与运维体验
- 发布流水线升级构建产物范围，支持 Windows 桌面版、Linux 服务端二进制、多架构 GHCR Docker 镜像，并可按标签或手动参数触发。 (#14)
- 发布脚本覆盖 SemVer 解析与防冲突递增、Conventional Commits 和 `bump:*` 标签识别、双语说明与 `CHANGELOG.md` 渲染，以及前端版本号同步更新。 (#14)
- 新增发布工作流及浏览器、API、并发和 Shell 注入防护回归测试，并将发布脚本测试纳入现有构建流水线。 (#13, #14, #15)

---

## English Release Notes

> This release introduces a standalone alert center and intelligent remediation tools, hardens the AI Ops workflow end to end, and adds automated bilingual release automation.

### ✨ New Features & Highlights
- Added a standalone “Alert Center” navigation page, separating alerts and event history from “Status Monitoring” and providing filtering by status, severity, category, server, and keywords, plus “Timeline / By Server” views. (#15)
- Added cross-page alert navigation: alert badges on monitoring cards, cluster and host views, and Server Manager cards now jump to the Alert Center and focus the relevant server. Workspace bootstrap data now includes active alert counts per server. (#15)
- Introduced a context-aware remediation engine covering all 34 built-in monitoring rules. It combines live host snapshots with alert context to generate root-cause analysis, evidence, troubleshooting steps, severity levels, and recovery guidance. (#15)
- Remediation cards support copying commands, running read-only checks in the terminal, safely filling mutating commands for manual confirmation, adopting baselines, and immediately retesting port or security drift. “AI Deep Diagnosis” opens AI Ops with the target host and a prefilled diagnostic prompt. (#15)
- Added bulk alert acknowledgment, manual resolution with debounce reset, and server-scoped cleanup of resolved alerts. (#15)
- Added PR-triggered automation that creates or updates a bilingual next-release PR and incrementally incorporates additional merged PRs while reevaluating the SemVer version and release notes. (#14)
- Added one-click release publication that creates an annotated Tag, a bilingual Draft GitHub Release, scheduled platform builds, and cleanups for temporary release branches and labels. (#14)
- Added a zero-dependency Node.js release core, AI adapter, and release bot with Merge, Squash, and Rebase support, structured fallback notes, and preservation of maintainer edits to the PR description or `CHANGELOG.md`. (#14)

### 🐛 Bug Fixes & Reliability
- Fixed first-message streaming responses in newly created AI Ops sessions, ensured streams stop on session or host changes, and restored complete streaming Markdown, optimistic user messages, and stop-generation controls. (#13)
- Fixed responsive grid layout, missing approval-action styles, narrow-screen overflow, patrol unread badges, MCP status-chip visibility, and deep links from Terminal Copilot to specific AI Ops tabs. (#13)
- Fixed numeric input jumps, missing Escape and keyboard handling, unintended IME Enter submission, and host-memory edits accidentally overwriting data for a different server after switching the dropdown selection. (#13)
- Hardened AI provider and SSE behavior: normalized CRLF and EOF buffering, surfaced inline OpenAI / Anthropic stream errors, merged consecutive Anthropic messages safely, and prevented ToolCall ID collisions across ReAct rounds. (#13)
- Improved concurrency, scheduling, state synchronization, and boundary handling across external MCP, patrols, host memory, Webhooks, approvals, and background tasks; exhausted ReAct iterations now produce an explicit summary. (#13)
- Fixed MCP token creation, enable/disable, deletion, status synchronization, and error feedback across the AI Ops and MCP interfaces. (#13)

### 🔒 Security & Hardening
- Added strict allowlisting and Shell escaping for dynamic remediation parameters to prevent command injection from host snapshot data, while separating read-only checks from mutating actions. (#15)
- Strengthened concurrency and security boundaries around external AI MCP, HITL approvals, patrol scheduling, and background execution, including safer handling of stream failures and stale approvals. (#13)
- Restricted the Copilot CLI environment in release automation, prioritized GitHub-native Copilot CLI, and validated AI-generated SemVer and release-note output before allowing it to affect the release. (#14)

### ⚙️ Build, CI/CD & Developer Experience
- Extended the release pipeline for Windows desktop builds, Linux server binaries, and multi-architecture GHCR Docker images, with support for tag-driven and manual workflow dispatch. (#14)
- Added SemVer parsing and conflict-safe increments, Conventional Commit and `bump:*` label detection, bilingual Markdown and `CHANGELOG.md` rendering, and frontend package-version synchronization. (#14)
- Added release automation, browser, API, concurrency, and Shell-injection regression tests, and integrated the release-bot test suite into the existing build pipeline. (#13, #14, #15)

---

### Included Changes / 包含的变更

- #13 fix(aiops): AI 智能运维全链路 Review 与修复（UI / 逻辑 / 并发与安全） (@icaruszezen)
- #14 feat(release): 新增 PR 合并后 AI 自动生成双语版本 PR 与一键发布工作流 (@icaruszezen)
- #15 feat(alerts): 独立「告警信息」菜单页、跨页服务器告警跳转与智能修复建议引擎 (@icaruszezen)

**Full Changelog**: https://github.com/icaruszezen/ServerNeedSafe/compare/v2.5.1...v2.6.0
