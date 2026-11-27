# AI 自动版本发布 PR 工作流说明 / Automated AI Release PR Guide

本仓库内置了全自动的 **AI 版本发布 PR 流水线**（[`auto-release.yml`](workflows/auto-release.yml) + [`release-bot.mjs`](scripts/release-bot.mjs)），实现**「合并业务 PR → 自动生成/增量合入带中英文说明的新版本 PR → 点击一次 Merge 一键发布完整新版本」**的零摩擦体验。

---

## 工作流程 / How It Works

1. **业务 PR 合并到 `main`**
   - 自动扫描自上一个 SemVer Tag（如 `v2.5.1`）以来**所有未发布的已合并 PR**（支持 Merge Commit / Squash / Rebase 三种合并方式）及直接提交。
   - 调用 GitHub 上的 AI（优先 **GitHub Copilot CLI**，次选自定义 **OpenAI 兼容 API**，未配置时自动降级为双语规则引擎兜底）分析改动内容，确定合理的语义化版本号（`patch` / `minor` / `major`）并撰写高质量的**中文 + English 双语版本说明**。
   - 自动基于最新 `main` 创建或重建滚动分支 `release/next`，更新 `web/package.json`、`web/package-lock.json` 与 `CHANGELOG.md`，并创建或更新 Release PR（标题 `chore(release): vX.Y.Z`，标签 `autorelease: pending`）。

2. **旧版本 PR 尚未合并时，又有新 PR 合并到 `main`**
   - 并发队列严格串行（`cancel-in-progress: false`），绝不丢 PR、不产生冲突。
   - 自动将新 PR **增量并入现有的未合并版本 PR**，基于最新 `main` 同步所有代码、重新评估语义化版本号（例如原有 `fix` 为 `v2.5.2`，新合入 `feat` 后自动升级为 `v2.6.0`）、重新生成涵盖全部 PR 的中英文说明，并在 Release PR 下发表变更摘要评论。

3. **点击一次「Merge pull request」一键发布**
   - 发布前如需微调文案，可直接编辑 Release PR 描述中 `<!-- sns-release-notes:start -->` 与 `<!-- sns-release-notes:end -->` 之间的内容（或直接修改分支上的 `CHANGELOG.md`），系统会自动识别并尊重您的手动修改。
   - 点击 **Merge** 后，工作流自动：
     1. 在精确的合并提交上创建并推送 annotated Git Tag `vX.Y.Z`；
     2. 创建包含完整中英文说明的 GitHub Release 草稿；
     3. 自动调度 [`build-release.yml`](workflows/build-release.yml) 构建注入 `vX.Y.Z` 版本号的 Windows 桌面版（`.exe` + 便携 `.zip`）、Linux 服务端二进制、`SHA256SUMS.txt` 与多架构 GHCR Docker 镜像；
     4. 产物上传完毕后自动将 Release 从草稿原子切换为 **Latest 正式发布**，确保内置自动更新器立即检测到完整资产；
     5. 自动将 PR 标签切换为 `autorelease: tagged` 并清理 `release/next` 临时分支。

---

## 一次性 GitHub 仓库配置 / One-Time Setup

### 1. 允许 GitHub Actions 创建 PR（必需）

打开仓库 **Settings → Actions → General → Workflow permissions**：
- 勾选 **☑ Allow GitHub Actions to create and approve pull requests** 并点击 **Save**。
- _（备选：也可在仓库 Secrets 中配置具有 `Contents: Read & write` + `Pull requests: Read & write` 权限的 Fine-Grained PAT，命名为 `RELEASE_GITHUB_TOKEN`。）_

### 2. 配置 GitHub AI 引擎（推荐：GitHub Copilot）

> 注：GitHub Models（`models.github.ai`）已于 2026 年 7 月 30 日正式下线，当前 GitHub 官方推荐通过 **GitHub Copilot CLI (`@github/copilot`)** 在 Actions 中调用 GitHub AI。

**方案 A（推荐）：使用 GitHub Copilot AI**
1. 前往 [GitHub Fine-Grained PAT 创建页](https://github.com/settings/personal-access-tokens/new) 创建令牌（账号需拥有 GitHub Copilot 订阅）；
2. 在 **Account permissions** 中授予 **`Copilot Requests: Read`** 权限；
3. 在仓库 **Settings → Secrets and variables → Actions → Secrets** 新增：
   - `COPILOT_GITHUB_TOKEN`：填入刚创建的 PAT。
4. _（可选）_ 在 **Variables** 中设置 `AI_MODEL`（如 `claude-sonnet-4.5`、`gpt-4.1`）以指定模型。

**方案 B（备选）：使用任意 OpenAI 兼容模型（Azure AI Foundry / OpenAI / DeepSeek / Gemini / OpenRouter 等）**
- 在 **Secrets** 中配置 `AI_API_KEY`；
- 在 **Variables** 中按需配置：
  - `AI_API_BASE_URL`（默认 `https://api.openai.com/v1`）
  - `AI_MODEL`（默认 `gpt-4.1-mini`）
  - `AI_PROVIDER`（可选：`auto` / `copilot` / `openai-compatible`，默认 `auto`）

> 若暂未配置上述任意 AI Secret，脚本仍可完整运行：会基于 Conventional Commits 规则自动计算版本号并生成结构化双语兜底说明，绝不阻塞发布流程。

---

## 进阶控制 / Advanced Controls

- **PR 标签微调版本号**：在业务 PR 上添加以下标签即可显式控制版本递进：
  - `bump:major` 或 `breaking`：强制主版本升级（`X+1.0.0`）
  - `bump:minor`：至少次版本升级（`X.Y+1.0`）
  - `bump:patch`：修订版本升级（`X.Y.Z+1`）
  - `skip-release`：此 PR 不触发且不纳入发布 PR
- **自定义 AI 撰写风格**：直接编辑 [`.github/release-notes-instructions.md`](release-notes-instructions.md)，无需改动任何脚本代码。
- **手动触发 / 预览（Dry Run）**：在 GitHub **Actions → AI Auto Release PR & One-Click Publish → Run workflow** 中可指定 `bump` 级别、`model` 或开启 `dry_run` 仅预览结果。
