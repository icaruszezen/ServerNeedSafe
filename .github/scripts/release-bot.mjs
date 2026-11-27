#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  LABEL_PENDING,
  LABEL_TAGGED,
  RELEASE_BRANCH,
  buildAIPrompt,
  detectBumpFromChanges,
  findLatestSemverTag,
  isReleaseCommit,
  isReleasePR,
  parseReleasePRMeta,
  parseSemver,
  reconcileBumpWithAI,
  renderBilingualReleaseNotes,
  renderReleasePRBody,
  resolveFinalReleaseNotes,
  resolveNextVersion,
  sanitizeActionLog,
  shouldSkipPR,
  updateWebPackageVersions,
  upsertChangelog,
} from './release-core.mjs';
import { generateReleaseWithAI } from './release-ai.mjs';

const GITHUB_API_BASE = (process.env.GITHUB_API_URL || 'https://api.github.com').replace(/\/+$/, '');
const BUILD_WORKFLOW_FILE = process.env.BUILD_WORKFLOW_FILE || 'build-release.yml';

function git(args, { cwd = process.cwd(), allowFail = false } = {}) {
  try {
    return execFileSync('git', args, {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 16 * 1024 * 1024,
    }).trim();
  } catch (err) {
    if (allowFail) return '';
    const stderr = err.stderr ? String(err.stderr).trim() : err.message;
    throw new Error(`git ${args.join(' ')} failed: ${stderr}`);
  }
}

function gitOk(args, { cwd = process.cwd() } = {}) {
  try {
    execFileSync('git', args, {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return true;
  } catch {
    return false;
  }
}

export function createGitHubClient({ token, repo, apiBase = GITHUB_API_BASE, fetchFn = globalThis.fetch }) {
  if (!token) throw new Error('Missing GITHUB_TOKEN');
  if (!repo || !repo.includes('/')) throw new Error(`Invalid GITHUB_REPOSITORY: ${repo}`);
  const [owner, repoName] = repo.split('/');

  async function request(method, endpoint, { body, allowStatuses = [] } = {}) {
    const url = endpoint.startsWith('http') ? endpoint : `${apiBase}${endpoint}`;
    const headers = {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'ServerNeedSafe-AutoRelease-Bot/1.0',
    };
    const init = { method, headers, signal: AbortSignal.timeout(30_000) };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }

    const resp = await fetchFn(url, init);
    const text = await resp.text();
    let json = null;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        json = text;
      }
    }

    if (!resp.ok && !allowStatuses.includes(resp.status)) {
      const msg = typeof json === 'object' && json?.message ? json.message : String(text).slice(0, 400);
      const err = new Error(`GitHub API ${method} ${endpoint} failed (${resp.status}): ${msg}`);
      err.status = resp.status;
      err.responseBody = json;
      throw err;
    }
    return { status: resp.status, data: json };
  }

  return {
    owner,
    repoName,
    repo,
    request,

    async ensureLabel(name, color, description) {
      const res = await request('POST', `/repos/${repo}/labels`, {
        body: { name, color, description },
        allowStatuses: [422],
      });
      return res.data;
    },

    async listOpenReleasePRs(base = 'main') {
      const head = encodeURIComponent(`${owner}:${RELEASE_BRANCH}`);
      const encodedBase = encodeURIComponent(base);
      const res = await request('GET', `/repos/${repo}/pulls?state=open&head=${head}&base=${encodedBase}&per_page=10`);
      return Array.isArray(res.data) ? res.data : [];
    },

    async getPR(number) {
      const res = await request('GET', `/repos/${repo}/pulls/${number}`);
      return res.data;
    },

    async listPRFiles(number) {
      const res = await request('GET', `/repos/${repo}/pulls/${number}/files?per_page=50`, {
        allowStatuses: [404],
      });
      if (!Array.isArray(res.data)) return [];
      return res.data.map((f) => f.filename).filter(Boolean);
    },

    async listCommitPRs(sha) {
      const res = await request('GET', `/repos/${repo}/commits/${sha}/pulls?per_page=10`, {
        allowStatuses: [404, 422],
      });
      return Array.isArray(res.data) ? res.data : [];
    },

    async createPR({ title, body, head, base }) {
      try {
        const res = await request('POST', `/repos/${repo}/pulls`, {
          body: { title, body, head, base },
        });
        return res.data;
      } catch (err) {
        if (err.status === 403 && /not permitted to create or approve pull requests/i.test(err.message)) {
          throw new Error(
            [
              err.message,
              '',
              '🔧 一次性修复方法 / One-time Fix:',
              '1. 打开仓库 Settings → Actions → General → Workflow permissions',
              '2. 勾选 "Allow GitHub Actions to create and approve pull requests" 并保存',
              '   （或在仓库 Secrets 中配置具有 Contents & Pull requests 读写权限的 RELEASE_GITHUB_TOKEN）',
            ].join('\n'),
          );
        }
        throw err;
      }
    },

    async updatePR(number, { title, body }) {
      const res = await request('PATCH', `/repos/${repo}/pulls/${number}`, {
        body: { title, body },
      });
      return res.data;
    },

    async addLabels(issueNumber, labels) {
      if (!labels || labels.length === 0) return;
      await request('POST', `/repos/${repo}/issues/${issueNumber}/labels`, {
        body: { labels },
      });
    },

    async removeLabel(issueNumber, label) {
      const encoded = encodeURIComponent(label);
      await request('DELETE', `/repos/${repo}/issues/${issueNumber}/labels/${encoded}`, {
        allowStatuses: [404],
      });
    },

    async commentOnIssue(issueNumber, body) {
      await request('POST', `/repos/${repo}/issues/${issueNumber}/comments`, {
        body: { body },
      });
    },

    async getReleaseByTag(tag) {
      // List recent releases including drafts (getReleaseByTag REST endpoint skips drafts!)
      const res = await request('GET', `/repos/${repo}/releases?per_page=100`);
      if (!Array.isArray(res.data)) return null;
      return res.data.find((r) => r.tag_name === tag) || null;
    },

    async createRelease({ tagName, name, body, draft = true, prerelease = false }) {
      const res = await request('POST', `/repos/${repo}/releases`, {
        body: {
          tag_name: tagName,
          name,
          body,
          draft,
          prerelease,
          generate_release_notes: false,
        },
      });
      return res.data;
    },

    async updateRelease(releaseId, { name, body, draft, prerelease }) {
      const payload = { name, body };
      if (typeof draft === 'boolean') payload.draft = draft;
      if (typeof prerelease === 'boolean') payload.prerelease = prerelease;
      const res = await request('PATCH', `/repos/${repo}/releases/${releaseId}`, {
        body: payload,
      });
      return res.data;
    },

    async generateGitHubNotes({ tagName, previousTagName }) {
      const res = await request('POST', `/repos/${repo}/releases/generate-notes`, {
        body: {
          tag_name: tagName,
          ...(previousTagName ? { previous_tag_name: previousTagName } : {}),
        },
      });
      return res.data?.body || '';
    },

    async dispatchBuildRelease(tagName, ref = 'main') {
      await request('POST', `/repos/${repo}/actions/workflows/${BUILD_WORKFLOW_FILE}/dispatches`, {
        body: {
          ref,
          inputs: {
            release_tag: tagName,
          },
        },
      });
    },

    async deleteBranch(branchName) {
      const encoded = branchName.split('/').map(encodeURIComponent).join('/');
      await request('DELETE', `/repos/${repo}/git/refs/heads/${encoded}`, {
        allowStatuses: [404, 422],
      });
    },
  };
}

function appendStepSummary(markdown) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) return;
  try {
    fs.appendFileSync(summaryPath, `${markdown}\n`, 'utf8');
  } catch (err) {
    console.warn(`[summary] Failed to write GITHUB_STEP_SUMMARY: ${err.message}`);
  }
}

function parseGitLogRecords(raw) {
  if (!raw) return [];
  const records = raw.split('\x1e').map((s) => s.trim()).filter(Boolean);
  return records
    .map((rec) => {
      const [sha, author, subject, body = ''] = rec.split('\x1f');
      return {
        sha: (sha || '').trim(),
        author: (author || '').trim(),
        subject: (subject || '').trim(),
        body: (body || '').trim(),
      };
    })
    .filter((r) => r.sha);
}

/**
 * Collect all merged PRs and direct non-release commits in `<baseTag>..HEAD`.
 */
export async function collectUnreleasedChanges({ cwd = process.cwd(), baseTag, gh, triggerPRNumber = null }) {
  const range = baseTag ? `${baseTag}..HEAD` : 'HEAD';
  const format = '%H%x1f%an%x1f%s%x1f%b%x1e';
  const firstParentRaw = git(['log', range, '--first-parent', `--format=${format}`], { cwd, allowFail: true });
  const firstParentCommits = parseGitLogRecords(firstParentRaw);

  const prNumbers = new Set();
  const commitToPRs = new Map();
  let apiLookups = 0;

  for (const commit of firstParentCommits) {
    if (isReleaseCommit(commit.subject)) {
      commitToPRs.set(commit.sha, ['__release__']);
      continue;
    }

    const found = [];
    const mergeMatch = /^Merge pull request #(\d+)\b/i.exec(commit.subject);
    if (mergeMatch) found.push(Number(mergeMatch[1]));

    const squashMatch = /\(#(\d+)\)\s*$/.exec(commit.subject);
    if (squashMatch) found.push(Number(squashMatch[1]));

    if (found.length === 0 && apiLookups < 40) {
      // Catch rebase-merged PRs or custom squash titles via GitHub API
      apiLookups++;
      const associated = await gh.listCommitPRs(commit.sha);
      for (const p of associated) {
        if (p?.merged_at && p?.number) {
          found.push(Number(p.number));
        }
      }
    }

    const uniqueFound = [...new Set(found)];
    for (const num of uniqueFound) prNumbers.add(num);
    if (uniqueFound.length > 0) {
      commitToPRs.set(commit.sha, uniqueFound);
    }
  }

  // Ensure the triggering merged PR is never missed due to custom squash title or API propagation lag
  if (Number.isInteger(triggerPRNumber) && triggerPRNumber > 0 && !prNumbers.has(triggerPRNumber)) {
    try {
      const trig = await gh.getPR(triggerPRNumber);
      if (trig?.merged_at && !isReleasePR(trig)) {
        const mergeSha = trig.merge_commit_sha;
        const inHead = !mergeSha || gitOk(['merge-base', '--is-ancestor', mergeSha, 'HEAD'], { cwd });
        const alreadyReleased = Boolean(
          baseTag && mergeSha && gitOk(['merge-base', '--is-ancestor', mergeSha, baseTag], { cwd }),
        );
        if (inHead && !alreadyReleased) prNumbers.add(triggerPRNumber);
      }
    } catch {
      // Ignore if lookup fails; git log scan remains authoritative
    }
  }

  const prs = [];
  const skippedPRs = [];
  const sortedNumbers = [...prNumbers].sort((a, b) => a - b);

  for (const num of sortedNumbers) {
    const pr = await gh.getPR(num);
    if (!pr || !pr.merged_at) continue;
    if (isReleasePR(pr)) continue;
    if (shouldSkipPR(pr)) {
      skippedPRs.push(num);
      continue;
    }
    const files = await gh.listPRFiles(num);
    prs.push({
      number: pr.number,
      title: pr.title || '',
      body: pr.body || '',
      author: pr.user?.login || 'unknown',
      labels: pr.labels || [],
      htmlUrl: pr.html_url || '',
      mergedAt: pr.merged_at,
      files,
    });
  }

  const directCommits = firstParentCommits.filter((c) => {
    if (isReleaseCommit(c.subject)) return false;
    const mapped = commitToPRs.get(c.sha);
    return !mapped || mapped.length === 0;
  });

  const diffStat = baseTag
    ? git(['diff', '--stat', `${baseTag}..HEAD`], { cwd, allowFail: true })
    : git(['diff', '--stat', '--root', 'HEAD'], { cwd, allowFail: true });

  return {
    prs,
    skippedPRs,
    directCommits,
    diffStat,
  };
}

/**
 * Mode 1: Prepare or update the rolling Release PR (`release/next` -> `main`).
 */
export async function runPrepare({
  cwd = process.cwd(),
  env = process.env,
  gh,
  execCopilotFn,
  fetchFn = globalThis.fetch,
  log = console.log,
} = {}) {
  const repoSlug = env.GITHUB_REPOSITORY;
  const baseBranch = String(env.BASE_BRANCH || 'main').trim() || 'main';
  const dryRun = String(env.DRY_RUN || 'false').toLowerCase() === 'true';
  const bumpOverride = String(env.BUMP_OVERRIDE || 'auto').trim().toLowerCase();
  const triggerPRNumber = env.TRIGGER_PR_NUMBER ? Number(env.TRIGGER_PR_NUMBER) : null;
  const triggerPRTitle = String(env.TRIGGER_PR_TITLE || '').trim();

  const mergedTags = git(['tag', '--merged', 'HEAD', '--list', 'v*'], { cwd, allowFail: true })
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean);
  const allTags = git(['tag', '--list', 'v*'], { cwd, allowFail: true })
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean);

  const latestTag = findLatestSemverTag(mergedTags);
  const baseTag = latestTag || 'v0.0.0';

  const pkgPath = path.join(cwd, 'web', 'package.json');
  const lockPath = path.join(cwd, 'web', 'package-lock.json');
  const changelogPath = path.join(cwd, 'CHANGELOG.md');
  const instructionsPath = path.join(cwd, '.github', 'release-notes-instructions.md');

  const packageJsonText = fs.readFileSync(pkgPath, 'utf8');
  const packageLockText = fs.existsSync(lockPath) ? fs.readFileSync(lockPath, 'utf8') : '';
  const pkgVersion = JSON.parse(packageJsonText).version || '0.0.0';

  log(`[prepare] Base tag=${baseTag}, web/package.json=${pkgVersion}`);

  const { prs, skippedPRs, directCommits, diffStat } = await collectUnreleasedChanges({
    cwd,
    baseTag: latestTag,
    gh,
    triggerPRNumber,
  });

  log(
    `[prepare] Found ${prs.length} unreleased PR(s), ${directCommits.length} direct commit(s), ${skippedPRs.length} skipped PR(s).`,
  );

  if (prs.length === 0 && directCommits.length === 0) {
    log(`[prepare] No unreleased changes since ${baseTag}; nothing to do.`);
    appendStepSummary(`### ℹ️ Auto Release Skipped\n\nNo unreleased changes found since \`${baseTag}\`.`);
    return { status: 'no_changes', baseTag };
  }

  const analysis = detectBumpFromChanges({ prs, directCommits });
  const customInstructions = fs.existsSync(instructionsPath)
    ? fs.readFileSync(instructionsPath, 'utf8')
    : '';

  const prompt = buildAIPrompt({
    repoSlug,
    baseTag,
    analysis,
    bumpOverride,
    prs,
    directCommits,
    diffStat,
    customInstructions,
  });

  const { content, aiMeta } = await generateReleaseWithAI({
    prompt,
    prs,
    directCommits,
    analysis,
    bumpOverride,
    config: {
      aiProvider: env.AI_PROVIDER || 'auto',
      copilotToken: env.COPILOT_GITHUB_TOKEN || '',
      aiApiKey: env.AI_API_KEY || '',
      aiBaseUrl: env.AI_API_BASE_URL || '',
      aiModel: env.AI_MODEL || '',
      env,
    },
    execCopilotFn,
    fetchFn,
    log,
  });

  const { bump, source: bumpSource } = reconcileBumpWithAI({
    aiBump: aiMeta.provider === 'fallback' ? null : content.bump,
    analysis,
    bumpOverride,
  });

  const resolved = resolveNextVersion({
    latestTag: baseTag,
    packageVersion: pkgVersion,
    bump,
    existingTags: allTags,
  });

  const bilingualNotes = renderBilingualReleaseNotes({
    repoSlug,
    baseTag: latestTag || '',
    nextTag: resolved.tag,
    content,
    prs,
    directCommits,
  });

  const prTitle = `chore(release): ${resolved.tag}`;
  const prBody = renderReleasePRBody({
    baseTag: resolved.baseTag,
    nextTag: resolved.tag,
    nextVersion: resolved.version,
    bump,
    bumpSource,
    content,
    bilingualNotes,
    prs,
    directCommits,
    aiMeta,
  });

  if (dryRun) {
    log(`[prepare][dry-run] Would prepare ${resolved.tag} (${bump}, provider=${aiMeta.provider})`);
    log('--- PREVIEW ---\n' + sanitizeActionLog(prBody));
    appendStepSummary(`### 🧪 Auto Release Dry Run (${resolved.tag})\n\n${bilingualNotes}`);
    return {
      status: 'dry_run',
      tag: resolved.tag,
      version: resolved.version,
      bump,
      aiMeta,
      prNumbers: prs.map((p) => p.number),
    };
  }

  // Prepare clean rolling branch release/next based on current HEAD (main)
  const originalRef = git(['rev-parse', 'HEAD'], { cwd });
  const dateStr = new Date().toISOString().slice(0, 10);

  git(['checkout', '-B', RELEASE_BRANCH, originalRef], { cwd });

  const { packageJsonText: nextPkgText, packageLockText: nextLockText } = updateWebPackageVersions({
    packageJsonText,
    packageLockText,
    nextVersion: resolved.version,
  });
  fs.writeFileSync(pkgPath, nextPkgText, 'utf8');
  if (nextLockText) {
    fs.writeFileSync(lockPath, nextLockText, 'utf8');
  }

  const existingChangelog = fs.existsSync(changelogPath) ? fs.readFileSync(changelogPath, 'utf8') : '';
  const nextChangelog = upsertChangelog(existingChangelog, {
    tag: resolved.tag,
    dateStr,
    bilingualNotes,
  });
  fs.writeFileSync(changelogPath, nextChangelog, 'utf8');

  git(['config', 'user.name', 'github-actions[bot]'], { cwd });
  git(['config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com'], { cwd });

  const filesToStage = ['web/package.json', 'CHANGELOG.md'];
  if (fs.existsSync(lockPath)) filesToStage.push('web/package-lock.json');
  git(['add', ...filesToStage], { cwd });

  const commitMsg = [
    `chore(release): prepare ${resolved.tag}`,
    '',
    `Included PRs: ${prs.map((p) => `#${p.number}`).join(', ') || 'direct commits'}`,
  ].join('\n');
  git(['commit', '-m', commitMsg], { cwd });

  git(['push', '--force', 'origin', `HEAD:refs/heads/${RELEASE_BRANCH}`], { cwd });

  await gh.ensureLabel(LABEL_PENDING, '0E8A16', 'Pending automated release PR (merge to publish)');
  await gh.ensureLabel(LABEL_TAGGED, '5319E7', 'Automated release PR has been tagged and published');

  const openReleasePRs = await gh.listOpenReleasePRs(baseBranch);
  let pr;
  let action;

  if (openReleasePRs.length > 0) {
    const existing = openReleasePRs[0];
    const prevMeta = parseReleasePRMeta(existing.body);
    pr = await gh.updatePR(existing.number, { title: prTitle, body: prBody });
    await gh.addLabels(pr.number, [LABEL_PENDING]);
    action = 'updated';

    const versionTransition =
      prevMeta?.tag && prevMeta.tag !== resolved.tag
        ? `版本号已自动升级：\`${prevMeta.tag}\` → **\`${resolved.tag}\`**`
        : `当前目标版本：**\`${resolved.tag}\`**`;
    const triggerLine = triggerPRNumber
      ? `已将新合并的 PR #${triggerPRNumber}${triggerPRTitle ? `（${triggerPRTitle}）` : ''} 自动并入本发布 PR。`
      : '已根据 `main` 分支最新变更重新生成本发布 PR。';

    await gh.commentOnIssue(
      pr.number,
      [
        `🔄 ${triggerLine}`,
        '',
        `- ${versionTransition}`,
        `- 共累计包含 **${prs.length}** 个 PR${directCommits.length > 0 ? ` + ${directCommits.length} 个直接提交` : ''}`,
        `- 说明生成引擎：\`${aiMeta.provider}\`${aiMeta.model ? ` (\`${aiMeta.model}\`)` : ''}`,
      ].join('\n'),
    );
    log(`[prepare] Updated existing Release PR #${pr.number} -> ${resolved.tag}`);
  } else {
    pr = await gh.createPR({
      title: prTitle,
      body: prBody,
      head: RELEASE_BRANCH,
      base: baseBranch,
    });
    await gh.addLabels(pr.number, [LABEL_PENDING]);
    action = 'created';
    log(`[prepare] Created new Release PR #${pr.number} -> ${resolved.tag}`);
  }

  appendStepSummary(
    [
      `### 🚀 Release PR ${action === 'created' ? 'Created' : 'Updated'}: \`${resolved.tag}\``,
      '',
      `- **PR**: [#${pr.number} ${prTitle}](${pr.html_url})`,
      `- **Version Bump**: \`${resolved.baseTag}\` → \`${resolved.tag}\` (\`${bump}\`)`,
      `- **Generator**: \`${aiMeta.provider}\`${aiMeta.model ? ` (\`${aiMeta.model}\`)` : ''}`,
      `- **Included PRs**: ${prs.map((p) => `#${p.number}`).join(', ') || 'None (direct commits)'}`,
    ].join('\n'),
  );

  return {
    status: action,
    prNumber: pr.number,
    prUrl: pr.html_url,
    tag: resolved.tag,
    version: resolved.version,
    bump,
    aiMeta,
    prNumbers: prs.map((p) => p.number),
  };
}

/**
 * Mode 2: Publish the Git tag, Draft GitHub Release (with bilingual notes), and dispatch build-release.yml
 * when the Release PR is merged by the user.
 */
export async function runPublish({
  cwd = process.cwd(),
  env = process.env,
  gh,
  log = console.log,
} = {}) {
  const prNumber = Number(env.TRIGGER_PR_NUMBER);
  if (!Number.isInteger(prNumber) || prNumber <= 0) {
    throw new Error(`Invalid TRIGGER_PR_NUMBER for publish: ${env.TRIGGER_PR_NUMBER}`);
  }

  const pr = await gh.getPR(prNumber);
  if (!pr?.merged) {
    log(`[publish] PR #${prNumber} is not merged; skipping.`);
    return { status: 'not_merged' };
  }
  if (!isReleasePR(pr)) {
    log(`[publish] PR #${prNumber} is not a managed Release PR; skipping.`);
    return { status: 'not_release_pr' };
  }

  const pkgPath = path.join(cwd, 'web', 'package.json');
  const changelogPath = path.join(cwd, 'CHANGELOG.md');
  const pkgVersion = JSON.parse(fs.readFileSync(pkgPath, 'utf8')).version;
  const parsed = parseSemver(pkgVersion);
  if (!parsed) {
    throw new Error(`Invalid SemVer in web/package.json at merge commit: ${pkgVersion}`);
  }

  const tag = parsed.tag;
  const isPrerelease = Boolean(parsed.prerelease);
  const mergeSha = pr.merge_commit_sha || git(['rev-parse', 'HEAD'], { cwd });
  const changelogText = fs.existsSync(changelogPath) ? fs.readFileSync(changelogPath, 'utf8') : '';

  const prMeta = parseReleasePRMeta(pr.body);
  let { notes, source: notesSource } = resolveFinalReleaseNotes({
    prBody: pr.body,
    changelogText,
    tag,
  });

  if (!notes) {
    log(`[publish] No bilingual notes found in PR body or CHANGELOG.md; falling back to GitHub generate-notes.`);
    notes = await gh.generateGitHubNotes({
      tagName: tag,
      previousTagName: prMeta?.baseTag || undefined,
    });
    notesSource = 'github_generated';
  }

  log(`[publish] Publishing ${tag} at ${mergeSha} (notesSource=${notesSource})`);

  // Create & push annotated tag if it does not already exist on origin
  const remoteTagCheck = git(['ls-remote', '--tags', 'origin', `refs/tags/${tag}`], { cwd, allowFail: true });
  let tagCreated = false;
  if (!remoteTagCheck) {
    git(['config', 'user.name', 'github-actions[bot]'], { cwd });
    git(['config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com'], { cwd });
    git(['tag', '-a', tag, mergeSha, '-m', `Release ${tag}`], { cwd });
    git(['push', 'origin', `refs/tags/${tag}`], { cwd });
    tagCreated = true;
    log(`[publish] Created and pushed tag ${tag}`);
  } else {
    log(`[publish] Tag ${tag} already exists on origin; continuing idempotently.`);
  }

  // Create or update Draft GitHub Release with bilingual notes (build-release.yml uploads binaries & publishes it atomically!)
  const releaseTitle = `ServerNeedSafe ${tag}`;
  const existingRelease = await gh.getReleaseByTag(tag);
  let release;
  if (!existingRelease) {
    release = await gh.createRelease({
      tagName: tag,
      name: releaseTitle,
      body: notes,
      draft: true,
      prerelease: isPrerelease,
    });
    log(`[publish] Created draft GitHub Release id=${release.id} for ${tag}`);
  } else if (existingRelease.draft) {
    release = await gh.updateRelease(existingRelease.id, {
      name: releaseTitle,
      body: notes,
      draft: true,
      prerelease: isPrerelease,
    });
    log(`[publish] Updated existing draft GitHub Release id=${release.id} for ${tag}`);
  } else {
    release = existingRelease;
    log(`[publish] GitHub Release ${tag} is already published (id=${release.id}).`);
  }

  // Trigger build-release.yml via workflow_dispatch (works natively with GITHUB_TOKEN + actions: write!)
  const dispatchRef = pr.base?.ref || 'main';
  let buildDispatched = false;
  if (release.draft || tagCreated) {
    await gh.dispatchBuildRelease(tag, dispatchRef);
    buildDispatched = true;
    log(`[publish] Dispatched ${BUILD_WORKFLOW_FILE} on ref=${dispatchRef} for release_tag=${tag}`);
  }

  // Swap PR labels and clean up rolling branch
  await gh.ensureLabel(LABEL_TAGGED, '5319E7', 'Automated release PR has been tagged and published');
  await gh.removeLabel(prNumber, LABEL_PENDING);
  await gh.addLabels(prNumber, [LABEL_TAGGED]);
  await gh.deleteBranch(RELEASE_BRANCH);

  const actionsUrl = `https://github.com/${gh.repo}/actions/workflows/${BUILD_WORKFLOW_FILE}`;
  await gh.commentOnIssue(
    prNumber,
    [
      `🎉 **已触发 \`${tag}\` 正式版本发布！ / Release \`${tag}\` triggered!**`,
      '',
      `- **Git Tag**: [\`${tag}\`](https://github.com/${gh.repo}/releases/tag/${tag})`,
      `- **发布说明来源 / Notes Source**: \`${notesSource}\``,
      `- **产物构建与发布 / Build & Publish**: 已自动调度 [CI & Auto Build](${actionsUrl}) 构建 Windows 桌面版 / Linux 二进制与多架构 Docker 镜像，完成后将自动上传校验并正式公开 GitHub Release。`,
    ].join('\n'),
  );

  appendStepSummary(
    [
      `### 🎉 Published Release Tag \`${tag}\``,
      '',
      `- **Tag**: \`${tag}\` (\`${mergeSha.slice(0, 12)}\`)`,
      `- **Notes Source**: \`${notesSource}\``,
      `- **Draft Release ID**: \`${release.id}\``,
      `- **Build Dispatched**: \`${buildDispatched}\` ([View Workflow](${actionsUrl}))`,
    ].join('\n'),
  );

  return {
    status: 'published',
    tag,
    releaseId: release.id,
    notesSource,
    buildDispatched,
  };
}

async function main() {
  const cmd = process.argv[2];
  if (!['prepare', 'publish'].includes(cmd)) {
    console.error('Usage: node .github/scripts/release-bot.mjs <prepare|publish>');
    process.exit(2);
  }

  const gh = createGitHubClient({
    token: process.env.GITHUB_TOKEN,
    repo: process.env.GITHUB_REPOSITORY,
  });

  if (cmd === 'prepare') {
    await runPrepare({ gh });
  } else {
    await runPublish({ gh });
  }
}

const isDirectRun =
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isDirectRun) {
  main().catch((err) => {
    console.error(sanitizeActionLog(err?.stack || err?.message || String(err)));
    process.exit(1);
  });
}
