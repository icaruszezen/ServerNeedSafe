import { spawn } from 'node:child_process';
import {
  buildFallbackReleaseContent,
  parseAIJsonResponse,
  sanitizeActionLog,
} from './release-core.mjs';

const DEFAULT_COPILOT_TIMEOUT_MS = 180_000;
const DEFAULT_HTTP_TIMEOUT_MS = 90_000;

/**
 * Build a minimal, secret-isolated environment for the GitHub Copilot CLI subprocess.
 * Never inherits unrelated secrets (e.g., DEPLOY_SSH_KEY, RELEASE_GITHUB_TOKEN, AI_API_KEY).
 */
export function buildIsolatedCopilotEnv(env, copilotToken) {
  const out = {};
  for (const key of ['PATH', 'HOME', 'RUNNER_TEMP', 'NODE_PATH', 'NODE_OPTIONS', 'TMPDIR', 'TEMP', 'TMP']) {
    if (env[key]) out[key] = env[key];
  }
  if (copilotToken) {
    out.COPILOT_GITHUB_TOKEN = copilotToken;
    out.GITHUB_TOKEN = copilotToken;
  }
  return out;
}

/**
 * Execute the GitHub Copilot CLI (`@github/copilot`) non-interactively with strict read-only/no-tool flags.
 */
export function defaultExecCopilot({
  copilotBin = 'copilot',
  prompt,
  model = '',
  copilotToken,
  timeoutMs = DEFAULT_COPILOT_TIMEOUT_MS,
  env = process.env,
}) {
  const args = [
    '--prompt',
    prompt,
    '--silent',
    '--no-ask-user',
    '--deny-tool',
    'write',
    '--deny-tool',
    'shell',
  ];
  if (model) {
    args.push('--model', model);
  }

  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let killTimer;

    const child = spawn(copilotBin, args, {
      env: buildIsolatedCopilotEnv(env, copilotToken),
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      killTimer = setTimeout(() => {
        try {
          child.kill('SIGKILL');
        } catch {
          // already exited
        }
      }, 5000);
    }, timeoutMs);

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString('utf8');
    });

    child.on('error', (err) => {
      clearTimeout(timeout);
      if (killTimer) clearTimeout(killTimer);
      reject(new Error(`Failed to invoke Copilot CLI (${copilotBin}): ${err.message}`));
    });

    child.on('close', (code) => {
      clearTimeout(timeout);
      if (killTimer) clearTimeout(killTimer);
      if (timedOut) {
        reject(new Error(`Copilot CLI timed out after ${Math.round(timeoutMs / 1000)}s`));
        return;
      }
      if (code !== 0) {
        const cleanErr = sanitizeActionLog(stderr || stdout).slice(0, 800);
        reject(new Error(`Copilot CLI exited with code ${code}: ${cleanErr}`));
        return;
      }
      resolve(stdout);
    });
  });
}

function redactSecret(text, secret) {
  if (!secret || !text) return String(text || '');
  return String(text).split(secret).join('***');
}

function normalizeChatCompletionsURL(baseUrl) {
  const raw = String(baseUrl || 'https://api.openai.com/v1').trim().replace(/\/+$/, '');
  const parsed = new URL(raw);
  const isLocal = parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost';
  if (parsed.protocol !== 'https:' && !(isLocal && parsed.protocol === 'http:')) {
    throw new Error(`Unsupported AI_API_BASE_URL protocol: ${parsed.protocol}`);
  }
  if (raw.endsWith('/chat/completions')) return raw;
  return `${raw}/chat/completions`;
}

/**
 * Call an OpenAI-compatible Chat Completions endpoint (OpenAI, Azure AI Foundry, Gemini OpenAI-compat, DeepSeek, OpenRouter, etc.).
 */
export async function callOpenAICompatible({
  apiKey,
  baseUrl = 'https://api.openai.com/v1',
  model = 'gpt-4.1-mini',
  systemPrompt,
  userPrompt,
  timeoutMs = DEFAULT_HTTP_TIMEOUT_MS,
  fetchFn = globalThis.fetch,
}) {
  const url = normalizeChatCompletionsURL(baseUrl);
  const chosenModel = model || 'gpt-4.1-mini';

  async function doRequest(withJsonMode) {
    const body = {
      model: chosenModel,
      temperature: 0.2,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
    };
    if (withJsonMode) {
      body.response_format = { type: 'json_object' };
    }

    const resp = await fetchFn(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });

    const text = await resp.text();
    if (!resp.ok) {
      const err = new Error(`HTTP ${resp.status}: ${redactSecret(text.slice(0, 500), apiKey)}`);
      err.status = resp.status;
      throw err;
    }

    const data = JSON.parse(text);
    const content = data?.choices?.[0]?.message?.content;
    if (typeof content !== 'string' || !content.trim()) {
      throw new Error('OpenAI-compatible response missing choices[0].message.content');
    }
    return content;
  }

  try {
    return await doRequest(true);
  } catch (err) {
    // Some OpenAI-compatible gateways reject response_format=json_object with HTTP 400/422; retry without it.
    if (err?.status === 400 || err?.status === 422) {
      return await doRequest(false);
    }
    throw err;
  }
}

/**
 * Generate release bump & bilingual notes using the configured AI provider chain:
 *   1. GitHub Copilot CLI (`COPILOT_GITHUB_TOKEN`) — GitHub's native AI CLI
 *   2. OpenAI-compatible API (`AI_API_KEY` + optional `AI_API_BASE_URL` / `AI_MODEL`)
 *   3. Deterministic bilingual fallback (never blocks releasing)
 */
export async function generateReleaseWithAI({
  prompt,
  prs,
  directCommits,
  analysis,
  bumpOverride = 'auto',
  config = {},
  execCopilotFn = defaultExecCopilot,
  fetchFn = globalThis.fetch,
  log = console.log,
}) {
  const providerPref = String(config.aiProvider || 'auto').trim().toLowerCase();
  const copilotToken = String(config.copilotToken || '').trim();
  const aiApiKey = String(config.aiApiKey || '').trim();
  const aiBaseUrl = String(config.aiBaseUrl || '').trim() || 'https://api.openai.com/v1';
  const aiModel = String(config.aiModel || '').trim();
  const errors = [];

  const tryCopilot =
    (providerPref === 'auto' || providerPref === 'copilot') && Boolean(copilotToken);
  const tryOpenAI =
    (providerPref === 'auto' || providerPref === 'openai-compatible' || providerPref === 'openai') &&
    Boolean(aiApiKey);

  // 1. GitHub Copilot CLI (Primary GitHub Native AI)
  if (tryCopilot) {
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        log(`[ai] Calling GitHub Copilot CLI (attempt ${attempt}/2${aiModel ? `, model=${aiModel}` : ''})...`);
        const promptText =
          attempt === 1
            ? prompt.combinedPrompt
            : `${prompt.combinedPrompt}\n\nIMPORTANT: Your previous response was not valid JSON. Return ONLY a single valid JSON object matching the exact schema with no extra text.`;
        const raw = await execCopilotFn({
          prompt: promptText,
          model: aiModel,
          copilotToken,
          timeoutMs: config.copilotTimeoutMs || DEFAULT_COPILOT_TIMEOUT_MS,
          env: config.env || process.env,
        });
        const content = parseAIJsonResponse(raw);
        return {
          content,
          aiMeta: {
            provider: 'copilot',
            model: aiModel || 'github-copilot-default',
            warning: '',
          },
        };
      } catch (err) {
        const msg = sanitizeActionLog(redactSecret(err.message, copilotToken));
        errors.push(`GitHub Copilot CLI (attempt ${attempt}): ${msg}`);
        log(`[ai] Warning: Copilot attempt ${attempt} failed: ${msg}`);
      }
    }
  }

  // 2. OpenAI-Compatible API (Secondary / BYOK)
  if (tryOpenAI) {
    const modelToUse = aiModel || 'gpt-4.1-mini';
    for (let attempt = 1; attempt <= 2; attempt++) {
      try {
        log(`[ai] Calling OpenAI-compatible API (${aiBaseUrl}, model=${modelToUse}, attempt ${attempt}/2)...`);
        const userText =
          attempt === 1
            ? prompt.userPrompt
            : `${prompt.userPrompt}\n\nIMPORTANT: Return ONLY one valid JSON object matching the exact required schema.`;
        const raw = await callOpenAICompatible({
          apiKey: aiApiKey,
          baseUrl: aiBaseUrl,
          model: modelToUse,
          systemPrompt: prompt.systemPrompt,
          userPrompt: userText,
          timeoutMs: config.httpTimeoutMs || DEFAULT_HTTP_TIMEOUT_MS,
          fetchFn,
        });
        const content = parseAIJsonResponse(raw);
        return {
          content,
          aiMeta: {
            provider: 'openai-compatible',
            model: modelToUse,
            warning: '',
          },
        };
      } catch (err) {
        const msg = sanitizeActionLog(redactSecret(err.message, aiApiKey));
        errors.push(`OpenAI-compatible API (attempt ${attempt}): ${msg}`);
        log(`[ai] Warning: OpenAI-compatible attempt ${attempt} failed: ${msg}`);
      }
    }
  }

  // 3. Deterministic Bilingual Fallback
  const fallbackContent = buildFallbackReleaseContent({
    prs,
    directCommits,
    analysis,
    bumpOverride,
  });

  const warning =
    errors.length > 0
      ? `AI 生成暂时失败，已自动降级为规则引擎生成双语说明（详情：${errors[errors.length - 1].slice(0, 180)}）。可稍后手动触发工作流重新生成。`
      : '尚未配置 `COPILOT_GITHUB_TOKEN`（GitHub Copilot AI）或 `AI_API_KEY` Secret，当前使用规则引擎生成双语更新说明。在仓库 Settings → Secrets 中配置后将自动由 AI 撰写。';

  log(`[ai] Falling back to deterministic bilingual generator. Reason: ${warning}`);
  return {
    content: fallbackContent,
    aiMeta: {
      provider: 'fallback',
      model: '',
      warning,
    },
  };
}
