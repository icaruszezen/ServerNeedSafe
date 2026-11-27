# Changelog

All notable changes to **ServerNeedSafe** are documented in this file.
本文件记录 **ServerNeedSafe** 每个正式版本的中英文更新日志。

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
