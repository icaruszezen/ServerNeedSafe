# Changelog

All notable changes to **ServerNeedSafe** are documented in this file.
本文件记录 **ServerNeedSafe** 每个正式版本的中英文更新日志。

## v2.9.0 (2026-11-27)

## 中文更新说明

> 新增官方漏洞监测与独立执行审批中心，并进一步打通告警、外部 AI 和服务器分组的日常运维体验。

### ✨ 新功能与核心增强
- 新增「漏洞监测」一级功能模块，支持滚动快讯、动态情报流、CVSS 等级与 CISA KEV 标识、官方修复版本、星标、已读、忽略及多维筛选，并提供详情侧滑抽屉与按需 AI 中文解读入口 (#30)。
- 集成 6 大领域、35 款主流应用目录与快捷场景预设；默认监看 Linux Kernel、OpenSSH、OpenSSL 和 Nginx，并支持 GitHub 仓库、OSV 包或自定义应用订阅 (#30)。
- 新增多源官方漏洞聚合引擎，整合 OSV.dev、GitHub Security Advisories、厂商安全公告和 CISA KEV；支持 CVE/GHSA 去重、代理、GitHub Token、AI 解读缓存以及可选高严重性或在野利用告警推送 (#30)。
- 新增侧边栏「执行审批」中心，统一展示 MCP 与内置 AI 的待审批、执行中、历史审批和异常记录，提供按步确认、安全熔断、一键批准/拒绝/中止、Unified Diff、实时进度及关联巡检跳转 (#28)。
- 执行审批中心支持按状态、来源、主机和关键词筛选，并可定位原排障会话或打开对应主机的终端 Copilot 面板；记录保持只读审计留痕 (#28)。
- 告警卡片在「AI 深度诊断」旁新增「复制 MCP 文案」按钮，可一键复制包含主机现场、告警指标、只读排查命令、修复参考和 MCP 工具链的结构化外部 AI 排障提示 (#31)。
- MCP 告警提示词由后端根据告警详情和实时快照生成，并兼容前端兜底构建；针对离线、主机密钥变更、告警恢复及 macOS/Darwin 主机提供差异化安全引导 (#31)。

### 🔒 安全与权限加固
- 新增统一 `GET /api/ai/approvals` 审批聚合接口及轻量摘要轮询，工作区启动数据拆分巡检未读数与待审批数；AI 运维徽标不再混入审批计数 (#28)。
- 控制台登录后每 12 秒轻量轮询审批摘要，页面隐藏时暂停、恢复前台时立即同步，并在出现新审批时更新徽标与 Toast 提醒 (#28)。
- 将漏洞监测设置和可选代理、GitHub Token 纳入加密存储，情报运行数据独立防抖落盘至 `vuln_runtime.json`，并接入备份、跨端同步快照及磁盘占用统计 (#30)。
- 为漏洞监测提供鉴权 API、级别与来源筛选、只读审计相关状态管理，并支持通过风险场景预设和自定义订阅控制监看范围 (#30)。
- 外部 AI MCP 配置页收起审批队列和轮询，仅保留轻量「前往执行审批」入口，飞书、钉钉、企微 Webhook、变更计划提示及巡检引导已同步指向新审批中心 (#28)。

### 🐛 问题修复与稳定性提升
- 替换服务器分组原生 `<datalist>`，新增可搜索、自定义定位的分组选择组件；展开时即使已有预填值也会完整展示候选分组，支持模糊筛选、键盘导航、IME 保护和一键清空 (#27)。
- 修复分组数据同步问题，合并服务器列表和分组配置中的去重分组并统计主机数；保存与新建分组前统一清理首尾空格 (#27)。
- 下拉菜单通过 `createPortal` 渲染并动态计算视口位置，窄屏自动约束宽度、空间不足时向上翻转、锚点移出视口时收起，同时适配弹窗裁剪、鼠标、触摸、浅色和暗黑主题 (#27)。

### ⚙️ 工程构建与运维体验
- 前端补充移动端分组下拉切换、独立审批中心、漏洞中心及告警 MCP 文案按钮的响应式与端到端测试覆盖 (#27, #28, #30, #31)。
- 新增漏洞源、CVSS、审批聚合、徽标解耦、鉴权和提示词等后端测试，前端单位测试与生产构建均已通过；相关 Go 包通过静态检查和竞态测试 (#28, #30, #31)。

---

## English Release Notes

> Adds an official vulnerability monitoring center and standalone execution approvals, while improving alert handling, external AI workflows, and server-group management.

### ✨ New Features & Highlights
- Adds a new “Vulnerability Monitoring” workspace for live security bulletins, an evolving intelligence feed, CVSS severity and CISA KEV indicators, official fixed versions, starring, read/ignored states, and advanced filtering (#30).
- Includes six categories and 35 mainstream applications, plus preset scenarios and custom subscriptions for GitHub repositories or OSV packages; Linux Kernel, OpenSSH, OpenSSL, and Nginx are monitored by default (#30).
- Introduces a multi-source intelligence engine aggregating OSV.dev, GitHub Security Advisories, vendor feeds, and CISA KEV, with CVE/GHSA deduplication, proxy support, GitHub token authentication, cached AI analysis, and optional push notifications for severe or actively exploited advisories (#30).
- Adds a dedicated “Execution Approvals” sidebar entry that consolidates MCP and built-in AI pending, running, completed, rejected, and failed approval records into one auditable center (#28).
- The approval center supports step-by-step confirmation, fail-safe locking, approve/reject/abort actions, Unified Diff previews, 1.5-second execution updates, inspection links, status/source/host/keyword filters, and direct navigation back to source sessions or terminal Copilot panels (#28).
- Alert cards now provide a “Copy MCP Prompt” action beside “AI Deep Diagnosis,” generating a structured external-AI troubleshooting prompt with host context, metrics, thresholds, read-only commands, remediation guidance, Runbook matches, and MCP tool steps (#31).
- MCP prompt generation is handled by the backend with a frontend fallback, and includes tailored safety guidance for offline hosts, host-key changes, resolved alerts, and macOS/Darwin systems (#31).

### 🔒 Security & Hardening
- Adds unified `GET /api/ai/approvals` aggregation and lightweight summary polling, while separating patrol unread counts from pending approvals in workspace bootstrap data (#28).
- Keeps approval status synchronized through a 12-second global poll that pauses while the page is hidden and resumes immediately when the foreground becomes active, with badge updates and Toast notifications for new requests (#28).
- Encrypts vulnerability settings, optional HTTP/SOCKS5 proxy configuration, and GitHub tokens in `secrets.enc`, while storing high-frequency intelligence independently in `vuln_runtime.json` and including it in backup, sync, and disk-usage views (#30).
- Protects vulnerability APIs with authentication and provides severity, source, application, KEV, patch, and read-state controls for managing monitored risk (#30).
- Removes the approval queue and polling from the external AI MCP configuration page, replacing it with a lightweight link to Execution Approvals; Feishu, DingTalk, WeCom webhooks and AI guidance now direct users to the new center (#28).

### 🐛 Bug Fixes & Reliability
- Replaces the browser-native `<datalist>` used for server groups with a searchable, custom-positioned selector that always exposes all existing groups even when a default value is prefilled (#27).
- Fixes group data synchronization by merging and deduplicating groups from server records and group configuration, with host counts and consistent trimming before save or creation (#27).
- Adds fuzzy filtering, IME composition protection, keyboard navigation, clear actions, mouse and touch support, and accurate mobile positioning for the new server-group selector (#27).
- Renders the dropdown through `createPortal`, constrains it to narrow viewports, flips it upward when needed, and closes it when its anchor leaves the viewport to prevent modal overflow and clipping issues (#27).

### ⚙️ Build, CI/CD & Developer Experience
- Expands responsive and E2E coverage for server-group switching, the approvals center, vulnerability monitoring, and alert MCP prompt actions (#27, #28, #30, #31).
- Adds backend coverage for intelligence sources, CVSS, approval aggregation, badge decoupling, authentication, and prompt generation; frontend unit tests and production builds pass, and Go vet/race tests complete successfully (#28, #30, #31).

---

### Included Changes / 包含的变更

- #27 fix(servers): 修复新建/编辑服务器时所属分组下拉框交互问题 (@icaruszezen)
- #28 feat(approvals): 将 MCP 执行审批独立为侧边栏「执行审批」中心 (@icaruszezen)
- #30 feat(vuln): 新增 7×24 主流应用官方漏洞监测中心与自选监看应用管理 (@icaruszezen)
- #31 feat(alerts): 告警卡片新增一键复制外部 MCP AI 诊断文案按钮 (@icaruszezen)

**Full Changelog**: https://github.com/icaruszezen/ServerNeedSafe/compare/v2.8.0...v2.9.0

## v2.8.0 (2026-11-27)

## 中文更新说明

> 本版本全面升级 AI 运维与多模型接入能力，新增批量审批执行、敏感信息一键屏蔽和最新模型参数适配，同时强化安全、可观测性与交互稳定性。

### ✨ 新功能与核心增强
- 新增统一的 `propose_change_plan` MCP 工具，可在一个有序计划中混合编排 SSH 命令与 SFTP 写入，最多支持 20 步，并为每一步设置独立主机、超时和遇错继续策略。外部大模型可通过 `wait_for_approval` 等待终态并立即获取完整进度与步骤结果。 (#23)
- 外部变更审批升级为完整批量工作流：界面按序展示全部步骤，支持局部勾选跳过、默认全选、安全拦截红框提示、实时执行回显和一键中止；批准后立即进入后台异步顺序执行，遇错时可停止后续步骤或按计划继续。 (#23)
- 支持前后步骤修改同一文件时自动生成链式 Unified Diff，并在计划合并为一条 Webhook 通知和一条自动变更记忆。守护进程重启时会恢复遗留运行任务的终态状态，同时兼容读取历史单步审批记录。 (#23)
- 新增「一键屏蔽关键信息」开关，默认关闭，可在展示层统一屏蔽 IP、域名、端口、服务器路径、凭据、密钥、邮件、手机号及常见敏感运维词汇，而不修改底层加密资产。 (#25)
- 屏蔽功能已覆盖全局 AGENTS.md、长期记忆、主机画像 2.0 和 Runbook 技能库，并与当前服务器清单、主机画像部署路径和自定义 SSH 参数联动；开启后会阻止编辑与保存以防止 `***` 被误写入存储。 (#25)
- AGENTS.md 屏蔽后可导出为 `AGENTS.masked.md`，Markdown 加粗、代码块与格式化渲染通过哨兵机制保持完整，恢复显示只会恢复原始明文且不会修改数据。 (#25)
- 大模型接入全面支持 OpenAI Chat Completions、OpenAI Responses、Anthropic Messages 和 Google Gemini 原生协议，并兼容第三方中转的智能补全、完整地址直连及 Bearer、`x-api-key`、`x-goog-api-key`、URL Query、免密等认证方式。 (#26)
- 排障对话、终端副驾驶、流式连通测试、后台巡检和上下文压缩均强制使用 SSE 流式请求，流式传输升级为建连、响应头和空闲超时；首字延迟与真实 Token Usage 可直接用于连通性诊断。 (#26)
- 新增最新模型目录快照，并支持从 `models.dev/api.json` 联网同步、在 OpenRouter 中回退，以及从当前接口的 `/models` 拉取可用模型；选定模型可自动回填上下文窗口、最大输入与最大输出参数。 (#26)
- 完全开放上下文窗口、输入输出 Token、温度、Top P 和推理强度等自定义配置，支持留空或设为 `0` 使用模型默认值，并可通过加密 `custom_headers` 与无字段白名单限制的 `extra_body_json` 深度合并任意参数。 (#26)

### 🔒 安全与权限加固
- MCP Token 越权主机、参数错误等请求继续在网关层直接拒绝；命中危险命令或敏感写入路径的步骤会以 `blocked` 状态安全入队、审计并禁止执行。 (#23)
- 批量计划支持审批时逐步跳过、实时取消及严格按原始顺序执行，并对续错策略和后台中止行为进行边界保护。 (#23)
- 敏感信息屏蔽引擎覆盖网络端点、SSH 配置、数据库连接串、PEM/SSH 密钥、JWT、Bearer、云厂商凭据、环境变量、身份证和手机号等高风险信息，同时保留时间、版本号、百分比等非敏感运维信息。 (#25)
- 模型配置继续采用加密存储和零知识防泄漏规则：敏感请求头自动脱敏，克隆端点可复用同端点加密 API Key；更换地址或协议时必须重新填写敏感头，防止凭据被带入错误接口。 (#26)
- 模型参数适配覆盖 GPT-5/6、Claude 4.6/5.5 Adaptive Thinking、Gemini 3/4、DeepSeek V4 和 Qwen4 等推理模型，包括模型族温度冲突规避、`reasoning` 与工具调用签名透传及最新 `thinkingLevel` / `thinkingBudget` 参数。 (#26)

### 🐛 问题修复与稳定性提升
- 修复外部 AI MCP 逐条审批无法表达多步运维序列、缺少执行进度、无法中途停止及旧任务状态恢复不完整的问题。 (#23)
- 修正批量审批列表对完整 Diff 和敏感正文的脱敏与精简展示，避免新内容或预览中意外暴露敏感信息。 (#23)
- 修复多类屏蔽规则中的误伤和泄漏边界，并用哨兵机制确保脱敏后的 Markdown、代码块和粗体渲染不会被破坏。 (#25)
- 修正模型连通性测试不再强制截断为 `max_tokens=64`，避免短输出掩盖真实接入问题，并正确拒绝非 SSE 反代响应及处理流式空闲超时。 (#26)
- 补强多轮工具调用中的思考签名、`reasoning_content`、Anthropic `redacted_thinking` 和 Responses API `reasoning` 项透传，避免多轮推理和工具执行后续轮次丢失上下文。 (#26)

### ⚙️ 工程构建与运维体验
- 新增敏感屏蔽引引擎的 11 组规则与边界测试、Markdown 记忆中心渲染测试，并将前端单元测试接入构建发布工作流。 (#25)
- AI 运维界面新增可折叠的实时思考过程卡片、流式首字延迟和用量结果展示，便于区分连接问题、推理延迟与实际模型输出。 (#26)
- 配置界面支持一键同步公开模型目录、一键拉取接口模型列表、复制同端点为新模型，以及在编辑或克隆时复用加密密钥并进行安全校验。 (#26)

---

## English Release Notes

> This release substantially upgrades AI operations and multi-provider integration with ordered batch approvals, one-click sensitive-data masking, and modern model parameter support, while improving security and runtime reliability.

### ✨ New Features & Highlights
- Added the unified `propose_change_plan` MCP tool, allowing one ordered plan to mix SSH commands and SFTP writes in up to 20 steps, with per-step host, timeout, and `continue_on_error` settings. External models can use `wait_for_approval` to wait for the terminal state and receive complete step progress and results. (#23)
- Upgraded external-change approvals into a full batch workflow: the console now displays every step in order, supports individual skips before approval, highlights blocked steps, streams live execution output, and provides one-click cancellation. Approved plans run asynchronously in the AI-defined sequence, stopping on errors or continuing only where configured. (#23)
- Added chained Unified Diffs when consecutive steps modify the same file on the same host, plus one aggregated Webhook notification and one consolidated automatic change-memory entry per plan. Restarting the daemon restores interrupted legacy tasks to terminal states and remains compatible with historical single-step approvals. (#23)
- Added a default-off “Mask Sensitive Information” switch that replaces IPs, domains, ports, server paths, credentials, keys, email addresses, phone numbers, and common sensitive operations terms in the display layer without changing encrypted stored data. (#25)
- Applied masking across global AGENTS.md, the long-term memory library, Host Memory 2.0, and the Runbook library, with dynamic awareness of server inventory, deployment paths, custom SSH ports, and host usernames. Editing and saving are blocked while masking is enabled to prevent placeholders from being written back to storage. (#25)
- Masked AGENTS.md content can be exported as `AGENTS.masked.md`. Sentinel handling preserves bold text, code blocks, and Markdown formatting, while restoring the view reveals the original plaintext without any data modification. (#25)
- Expanded native AI provider support to OpenAI Chat Completions, OpenAI Responses, Anthropic Messages, and Google Gemini, including third-party relay compatibility for smart URL completion, direct full-URL connections, and multiple authentication modes such as Bearer, `x-api-key`, `x-goog-api-key`, URL query keys, and no-auth. (#26)
- Made SSE streaming mandatory across troubleshooting chat, Terminal Copilot, connectivity tests, patrol analysis, and context compaction. The transport now separates connection, response-header, and idle timeouts, reports first-token latency, and exposes real usage statistics. (#26)
- Added an offline model-catalog snapshot plus online synchronization from `models.dev/api.json`, with OpenRouter fallback and provider `/models` discovery for OpenAI, Anthropic, and Gemini. Selecting a model automatically fills context-window, input, and output defaults. (#26)
- Removed frontend and backend numeric limits for context-window, input/output token, temperature, top-p, and reasoning-effort settings. Zero or blank values can defer to model defaults, while encrypted custom headers and RFC 7396 deep-merging `extra_body_json` allow unrestricted compatible parameters. (#26)

### 🔒 Security & Hardening
- Keeps MCP authorization and parameter validation at the gateway boundary; steps that trigger blocked commands or sensitive write-path rules are queued as `blocked`, audited, red-highlighted, and prohibited from execution. (#23)
- Added approval-time step skipping, cancellation, strict original-order execution, and guarded handling for error continuation and interrupted background tasks. (#23)
- Masked sensitive network endpoints, SSH configuration, database connection strings, PEM and SSH keys, JWT/Bearer credentials, cloud tokens, environment assignments, identities, and phone numbers while preserving timestamps, versions, and percentages. (#25)
- Retained zero-knowledge and encrypted credential protections for provider configuration: sensitive headers are masked, same-endpoint cloning reuses the encrypted API key, and changing a base URL or protocol requires re-entering sensitive custom headers. (#26)
- Added model-family adaptations for GPT-5/6, Claude 4.6/5.5 Adaptive Thinking, Gemini 3/4, DeepSeek V4, and Qwen4, covering reasoning parameter conflicts, thought signatures, and the latest `thinkingLevel` / `thinkingBudget` formats. (#26)

### 🐛 Bug Fixes & Reliability
- Fixed the inability of external MCP workflows to represent ordered multi-step operations, track progress, stop mid-run, or recover legacy-running approvals reliably. (#23)
- Improved batch approval previews and lists so full Diff content and sensitive proposal text are safely summarized or masked. (#23)
- Hardened masking boundaries against false positives and accidental leaks, while ensuring placeholders do not break Markdown, code, or bold formatting. (#25)
- Removed the forced `max_tokens=64` truncation from connectivity tests, preventing misleading connection checks, and now rejects non-SSE proxy responses and reports streaming idle timeouts explicitly. (#26)
- Strengthened multi-turn reasoning and tool-call state transfer for `reasoning_content`, Anthropic `redacted_thinking`, interleaved signatures, and Responses API `reasoning` items. (#26)

### ⚙️ Build, CI/CD & Developer Experience
- Added 11 rule and boundary tests for the masking engine plus Markdown memory-center rendering tests, with frontend test coverage integrated into the build workflow. (#25)
- Added collapsible live reasoning cards, first-token latency, and usage reporting to AI conversation and Terminal Copilot interfaces. (#26)
- Improved provider configuration with one-click catalog synchronization, `/models` discovery, same-endpoint cloning, automatic model-default backfill, and encrypted API-key reuse safeguards. (#26)

---

### Included Changes / 包含的变更

- #23 feat(mcp): 外部 AI 变更审批升级为有序批量执行计划与一键按序批准 (@icaruszezen)
- #25 feat(ai-memory): Agent 与记忆中心新增一键屏蔽关键信息功能 (@icaruszezen)
- #26 feat(aiops): 优化大模型 API 接入（四协议纯流式、最新模型参数适配、模型目录拉取与无限制自定义配置） (@icaruszezen)

**Full Changelog**: https://github.com/icaruszezen/ServerNeedSafe/compare/v2.7.1...v2.8.0

## v2.7.1 (2026-11-27)

## 中文更新说明

> 统一复制操作并增加兼容降级方案，让 HTTP 局域网访问及受限浏览器环境中的常用复制功能更加可靠。

### 🐛 问题修复与稳定性提升
- 新增统一的剪贴板复制工具：安全上下文优先使用浏览器剪贴板 API；在 HTTP 等非安全上下文或原生写入失败时，自动尝试兼容性降级方案，避免复制操作直接报错。（#21）
- 将该方案应用于 MCP 地址、令牌及客户端配置，告警处置命令、升级命令、AI 建议命令和 SSH 公钥复制；降级操作完成后会清理临时元素并恢复原选区与焦点。（#21）

---

## English Release Notes

> Unified clipboard handling with a compatibility fallback makes common copy actions more reliable over HTTP and in restricted browser environments.

### 🐛 Bug Fixes & Reliability
- Added a shared clipboard utility that prefers the browser Clipboard API in secure contexts and falls back to a compatibility method when accessed over HTTP or when native writes fail, preventing copy actions from failing outright. (#21)
- Applied the fallback to MCP endpoints, tokens and client configuration, alert remediation and upgrade commands, AI suggestions, and SSH public keys. Temporary elements are cleaned up, and the previous selection and focus are restored afterward. (#21)

---

### Included Changes / 包含的变更

- #21 fix(web): add clipboard copy fallback for HTTP/non-secure contexts (@icaruszezen)

**Full Changelog**: https://github.com/icaruszezen/ServerNeedSafe/compare/v2.7.0...v2.7.1

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
