import React, { useMemo, useState } from 'react';
import {
  ChevronDown,
  ChevronRight,
  CloudDownload,
  Copy,
  Cpu,
  Edit3,
  KeyRound,
  Plus,
  RefreshCw,
  Search,
  Sliders,
  Sparkles,
  Trash2,
  X,
} from 'lucide-react';
import { api } from '../api';
import type {
  AIAuthMode,
  AICustomHeader,
  AIEndpointMode,
  AIModelCatalogEntry,
  AIOverviewResponse,
  AIProtocol,
  AIProviderView,
  AIReasoningEffort,
  ProviderPreset,
} from '../types';

interface AIProviderConfigTabProps {
  overview: AIOverviewResponse | null;
  onReloadOverview: () => Promise<void>;
  onNotify: (msg: string) => void;
}

interface CustomHeaderDraft {
  key: string;
  value: string;
  valuePreview?: string;
  isSensitive?: boolean;
  hasStoredValue?: boolean;
}

interface ProviderFormState {
  id: string;
  clone_from_id: string;
  clone_source_name: string;
  name: string;
  protocol: AIProtocol;
  base_url: string;
  endpoint_mode: AIEndpointMode;
  auth_mode: AIAuthMode;
  api_key: string;
  model: string;
  context_window: string;
  max_input_tokens: string;
  max_output_tokens: string;
  temperature: string;
  top_p: string;
  reasoning_effort: AIReasoningEffort;
  custom_headers: CustomHeaderDraft[];
  extra_body_json: string;
  set_active: boolean;
}

const PROTOCOL_LABELS: Record<AIProtocol, string> = {
  openai: 'OpenAI Chat 兼容',
  openai_responses: 'OpenAI Responses',
  anthropic: 'Anthropic Claude',
  gemini: 'Google Gemini',
};

const REASONING_LABELS: Record<AIReasoningEffort, string> = {
  '': '跟随模型默认',
  off: '关闭思考 (off)',
  low: '低 (low)',
  medium: '中 (medium)',
  high: '高 (high)',
  max: '最高 (max / xhigh)',
};

function makeEmptyForm(): ProviderFormState {
  return {
    id: '',
    clone_from_id: '',
    clone_source_name: '',
    name: 'OpenAI 官方 (Responses API)',
    protocol: 'openai_responses',
    base_url: 'https://api.openai.com/v1',
    endpoint_mode: 'auto',
    auth_mode: 'auto',
    api_key: '',
    model: 'gpt-6.2-sol',
    context_window: '1050000',
    max_input_tokens: '922000',
    max_output_tokens: '128000',
    temperature: '',
    top_p: '',
    reasoning_effort: '',
    custom_headers: [],
    extra_body_json: '',
    set_active: true,
  };
}

function formatTokensCompact(n?: number): string {
  if (!n || n <= 0) return '默认';
  if (n >= 1000000) {
    const m = n / 1000000;
    return `${Number.isInteger(m) ? m : m.toFixed(2)}M`;
  }
  if (n >= 1000) {
    const k = Math.round(n / 1000);
    return `${k}K`;
  }
  return String(n);
}

function parseNonNegInt(raw: string): number {
  const cleaned = raw.trim().replace(/,/g, '');
  if (!cleaned) return 0;
  const n = Number(cleaned);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.floor(n);
}

function parseOptionalNum(raw: string): number | null {
  const cleaned = raw.trim();
  if (!cleaned) return null;
  const n = Number(cleaned);
  if (!Number.isFinite(n)) return null;
  return n;
}

export const AIProviderConfigTab: React.FC<AIProviderConfigTabProps> = ({
  overview,
  onReloadOverview,
  onNotify,
}) => {
  const [provForm, setProvForm] = useState<ProviderFormState>(makeEmptyForm);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [testingProvId, setTestingProvId] = useState<string>('');
  const [testResultBanner, setTestResultBanner] = useState<{
    ok: boolean;
    text: string;
  } | null>(null);

  // Model catalog & provider /models discovery state
  const [syncingCatalog, setSyncingCatalog] = useState(false);
  const [fetchingModels, setFetchingModels] = useState(false);
  const [discoveredModels, setDiscoveredModels] = useState<AIModelCatalogEntry[]>([]);
  const [showModelPicker, setShowModelPicker] = useState(false);
  const [modelSearch, setModelSearch] = useState('');

  const catalogModels = useMemo(
    () => overview?.model_catalog?.models || [],
    [overview?.model_catalog?.models]
  );

  const combinedModelOptions = useMemo(() => {
    const byKey = new Map<string, AIModelCatalogEntry>();
    for (const m of discoveredModels) {
      byKey.set(m.id.toLowerCase(), m);
    }
    for (const m of catalogModels) {
      const k = m.id.toLowerCase();
      if (!byKey.has(k)) {
        byKey.set(k, m);
      }
    }
    const all = Array.from(byKey.values());
    const q = modelSearch.trim().toLowerCase();
    const filtered = q
      ? all.filter(
          (m) =>
            m.id.toLowerCase().includes(q) ||
            (m.name || '').toLowerCase().includes(q) ||
            (m.vendor || '').toLowerCase().includes(q)
        )
      : all;

    // Sort discovered provider models first, then protocol-matching catalog entries
    return filtered
      .sort((a, b) => {
        const aDisc = a.source === 'provider' ? 0 : 1;
        const bDisc = b.source === 'provider' ? 0 : 1;
        if (aDisc !== bDisc) return aDisc - bDisc;
        const aProto = a.protocol === provForm.protocol ? 0 : 1;
        const bProto = b.protocol === provForm.protocol ? 0 : 1;
        if (aProto !== bProto) return aProto - bProto;
        return (b.release_date || '').localeCompare(a.release_date || '');
      })
      .slice(0, 80);
  }, [catalogModels, discoveredModels, modelSearch, provForm.protocol]);

  const matchedCatalogSpec = useMemo(() => {
    const raw = provForm.model.trim().toLowerCase();
    if (!raw) return null;
    const stripVendor = (s: string) => {
      const clean = s.replace(/^models\//, '');
      const idx = clean.lastIndexOf('/');
      return idx >= 0 ? clean.slice(idx + 1) : clean;
    };
    const targetCanon = stripVendor(raw);
    const pool = [...discoveredModels, ...catalogModels];
    return (
      pool.find((m) => m.id.toLowerCase() === raw) ||
      pool.find((m) => stripVendor(m.id.toLowerCase()) === targetCanon) ||
      null
    );
  }, [provForm.model, discoveredModels, catalogModels]);

  const extraBodyValidationError = useMemo(() => {
    const trimmed = provForm.extra_body_json.trim();
    if (!trimmed) return '';
    try {
      const parsed = JSON.parse(trimmed);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return '必须是合法的 JSON 对象（以 { 开头，以 } 结尾）';
      }
      return '';
    } catch (e: any) {
      return `JSON 语法错误: ${e?.message || '请检查括号与引号'}`;
    }
  }, [provForm.extra_body_json]);

  const buildCustomHeadersPayload = (drafts: CustomHeaderDraft[]): AICustomHeader[] => {
    return drafts
      .map((d) => ({ key: d.key.trim(), value: d.value.trim() }))
      .filter((d) => d.key !== '');
  };

  const applyPreset = (preset: ProviderPreset) => {
    setProvForm({
      id: '',
      clone_from_id: '',
      clone_source_name: '',
      name: preset.name,
      protocol: preset.protocol,
      base_url: preset.base_url,
      endpoint_mode: preset.endpoint_mode || 'auto',
      auth_mode: preset.auth_mode || 'auto',
      api_key: '',
      model: preset.default_model,
      context_window: preset.context_window ? String(preset.context_window) : '0',
      max_input_tokens: preset.max_input_tokens ? String(preset.max_input_tokens) : '0',
      max_output_tokens: preset.max_output_tokens ? String(preset.max_output_tokens) : '0',
      temperature: '',
      top_p: '',
      reasoning_effort: '',
      custom_headers: [],
      extra_body_json: '',
      set_active: true,
    });
    setDiscoveredModels([]);
    setTestResultBanner(null);
  };

  const applyModelEntryDefaults = (entry: AIModelCatalogEntry, notify = false) => {
    setProvForm((prev) => ({
      ...prev,
      model: entry.id,
      context_window: entry.context_window ? String(entry.context_window) : prev.context_window,
      max_input_tokens: entry.max_input_tokens ? String(entry.max_input_tokens) : prev.max_input_tokens,
      max_output_tokens: entry.max_output_tokens ? String(entry.max_output_tokens) : prev.max_output_tokens,
    }));
    setShowModelPicker(false);
    if (notify) {
      onNotify(
        `已为 ${entry.id} 填充默认配置（窗口 ${formatTokensCompact(entry.context_window)} / 输入 ${formatTokensCompact(entry.max_input_tokens)} / 输出 ${formatTokensCompact(entry.max_output_tokens)}），可随时自由修改`
      );
    }
  };

  const editExistingProvider = (p: AIProviderView) => {
    const hdrs: CustomHeaderDraft[] = (p.custom_headers || []).map((h) => ({
      key: h.key,
      value: h.is_sensitive ? '' : h.value_preview,
      valuePreview: h.value_preview,
      isSensitive: h.is_sensitive,
      hasStoredValue: h.has_value,
    }));
    const hasAdv =
      (p.auth_mode && p.auth_mode !== 'auto') ||
      (p.endpoint_mode && p.endpoint_mode !== 'auto') ||
      Boolean(p.reasoning_effort) ||
      p.temperature !== undefined && p.temperature !== null ||
      p.top_p !== undefined && p.top_p !== null ||
      hdrs.length > 0 ||
      Boolean(p.extra_body_json);
    setShowAdvanced(Boolean(hasAdv));
    setProvForm({
      id: p.id,
      clone_from_id: '',
      clone_source_name: '',
      name: p.name,
      protocol: p.protocol,
      base_url: p.base_url,
      endpoint_mode: p.endpoint_mode || 'auto',
      auth_mode: p.auth_mode || 'auto',
      api_key: '',
      model: p.model,
      context_window: String(p.context_window || 0),
      max_input_tokens: String(p.max_input_tokens || 0),
      max_output_tokens: String(p.max_output_tokens ?? p.max_tokens ?? 0),
      temperature: p.temperature !== undefined && p.temperature !== null ? String(p.temperature) : '',
      top_p: p.top_p !== undefined && p.top_p !== null ? String(p.top_p) : '',
      reasoning_effort: p.reasoning_effort || '',
      custom_headers: hdrs,
      extra_body_json: p.extra_body_json || '',
      set_active: overview?.active_provider_id === p.id,
    });
    setDiscoveredModels([]);
    setTestResultBanner(null);
  };

  const cloneExistingProvider = (p: AIProviderView) => {
    const hdrs: CustomHeaderDraft[] = (p.custom_headers || []).map((h) => ({
      key: h.key,
      value: h.is_sensitive ? '' : h.value_preview,
      valuePreview: h.value_preview,
      isSensitive: h.is_sensitive,
      hasStoredValue: h.has_value,
    }));
    setProvForm({
      id: '',
      clone_from_id: p.id,
      clone_source_name: p.name,
      name: `${p.name} (副本)`,
      protocol: p.protocol,
      base_url: p.base_url,
      endpoint_mode: p.endpoint_mode || 'auto',
      auth_mode: p.auth_mode || 'auto',
      api_key: '',
      model: p.model,
      context_window: String(p.context_window || 0),
      max_input_tokens: String(p.max_input_tokens || 0),
      max_output_tokens: String(p.max_output_tokens ?? p.max_tokens ?? 0),
      temperature: p.temperature !== undefined && p.temperature !== null ? String(p.temperature) : '',
      top_p: p.top_p !== undefined && p.top_p !== null ? String(p.top_p) : '',
      reasoning_effort: p.reasoning_effort || '',
      custom_headers: hdrs,
      extra_body_json: p.extra_body_json || '',
      set_active: true,
    });
    setDiscoveredModels([]);
    setTestResultBanner(null);
    onNotify(`已载入「${p.name}」为模板，保持相同地址与协议可直接复用加密 API Key，修改模型名称后保存即可`);
  };

  const handleSyncModelCatalog = async () => {
    setSyncingCatalog(true);
    try {
      const res = await api.syncAIModelCatalog();
      onNotify(
        `已同步最新公开模型默认配置（来源：${res.model_catalog.source}，共 ${res.model_catalog.models.length} 款模型）`
      );
      await onReloadOverview();
    } catch (err: any) {
      onNotify(err?.message || '同步最新公开模型配置失败，将继续使用本地内置模型目录');
    } finally {
      setSyncingCatalog(false);
    }
  };

  const handleFetchProviderModels = async () => {
    if (!provForm.base_url.trim()) {
      onNotify('请先填写 API Base URL');
      return;
    }
    setFetchingModels(true);
    try {
      const res = await api.fetchAIProviderModels({
        id: provForm.id || undefined,
        clone_from_id: provForm.clone_from_id || undefined,
        protocol: provForm.protocol,
        base_url: provForm.base_url,
        endpoint_mode: provForm.endpoint_mode,
        auth_mode: provForm.auth_mode,
        api_key: provForm.api_key || undefined,
        custom_headers: buildCustomHeadersPayload(provForm.custom_headers),
      });
      setDiscoveredModels(res.models || []);
      setShowModelPicker(true);
      setModelSearch('');
      onNotify(`已从接口拉取 ${res.count} 个可用模型，点击模型即可自动填充默认上下文与输入/输出参数`);
    } catch (err: any) {
      onNotify(err?.message || '拉取接口模型列表失败');
    } finally {
      setFetchingModels(false);
    }
  };

  const handleSaveProvider = async (e: React.FormEvent) => {
    e.preventDefault();
    if (extraBodyValidationError) {
      onNotify(extraBodyValidationError);
      return;
    }
    const maxOut = parseNonNegInt(provForm.max_output_tokens);
    const maxIn = parseNonNegInt(provForm.max_input_tokens);
    const ctxWin = parseNonNegInt(provForm.context_window);
    const temp = parseOptionalNum(provForm.temperature);
    const topP = parseOptionalNum(provForm.top_p);

    try {
      await api.upsertAIProvider({
        id: provForm.id || undefined,
        clone_from_id: provForm.clone_from_id || undefined,
        name: provForm.name,
        protocol: provForm.protocol,
        base_url: provForm.base_url,
        endpoint_mode: provForm.endpoint_mode,
        auth_mode: provForm.auth_mode,
        api_key: provForm.api_key || undefined,
        model: provForm.model,
        max_tokens: maxOut,
        max_output_tokens: maxOut,
        max_input_tokens: maxIn,
        context_window: ctxWin,
        temperature: temp,
        top_p: topP,
        reasoning_effort: provForm.reasoning_effort,
        custom_headers: buildCustomHeadersPayload(provForm.custom_headers),
        extra_body_json: provForm.extra_body_json.trim(),
        set_active: provForm.set_active,
      });
      setProvForm((prev) => ({
        ...prev,
        id: '',
        clone_from_id: '',
        clone_source_name: '',
        api_key: '',
      }));
      onNotify('大模型供应商配置已通过 XChaCha20-Poly1305 加密保存');
      await onReloadOverview();
    } catch (err: any) {
      onNotify(err?.message || '保存模型配置失败');
    }
  };

  const handleTestProvider = async (target?: AIProviderView) => {
    if (!target && extraBodyValidationError) {
      onNotify(extraBodyValidationError);
      return;
    }
    const id = target ? target.id : provForm.id;
    setTestingProvId(id || '__form__');
    setTestResultBanner(null);
    try {
      const res = await api.testAIProvider(
        target
          ? {
              id: target.id,
              protocol: target.protocol,
              base_url: target.base_url,
              endpoint_mode: target.endpoint_mode,
              auth_mode: target.auth_mode,
              model: target.model,
            }
          : {
              id: provForm.id || undefined,
              clone_from_id: provForm.clone_from_id || undefined,
              protocol: provForm.protocol,
              base_url: provForm.base_url,
              endpoint_mode: provForm.endpoint_mode,
              auth_mode: provForm.auth_mode,
              api_key: provForm.api_key || undefined,
              model: provForm.model,
              max_output_tokens: parseNonNegInt(provForm.max_output_tokens),
              temperature: parseOptionalNum(provForm.temperature),
              top_p: parseOptionalNum(provForm.top_p),
              reasoning_effort: provForm.reasoning_effort,
              custom_headers: buildCustomHeadersPayload(provForm.custom_headers),
              extra_body_json: provForm.extra_body_json.trim(),
            }
      );
      const ttftPart = res.first_token_ms ? ` · 首字 ${res.first_token_ms}ms` : '';
      const usagePart = res.usage?.total_tokens
        ? ` · 用量 ${res.usage.total_tokens.toLocaleString()} tok`
        : '';
      const msg = `流式连通成功 · 总耗时 ${res.latency_ms}ms${ttftPart}${usagePart} · 回复：「${res.reply}」`;
      setTestResultBanner({ ok: true, text: msg });
      onNotify(msg);
    } catch (err: any) {
      const msg = err?.message || '模型接口流式连通测试失败';
      setTestResultBanner({ ok: false, text: msg });
      onNotify(msg);
    } finally {
      setTestingProvId('');
    }
  };

  const catalogInfo = overview?.model_catalog;

  return (
    <div className="page-body">
      {/* Model Default Catalog Sync Bar */}
      <div className="ai-catalog-sync-bar">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', minWidth: 0 }}>
          <Sparkles size={15} style={{ color: 'var(--accent-teal)', flexShrink: 0 }} />
          <div style={{ fontSize: 12.5, lineHeight: 1.45 }}>
            <strong>最新模型默认配置目录</strong>
            <span style={{ color: 'var(--text-muted)', marginLeft: 8 }}>
              当前已载入 {catalogModels.length} 款模型默认上下文与输入/输出参数（来源：
              {catalogInfo?.source === 'builtin' || !catalogInfo?.source
                ? '内置 2026 离线快照'
                : catalogInfo.source}
              {catalogInfo?.synced_at
                ? ` · 同步于 ${new Date(catalogInfo.synced_at).toLocaleString('zh-CN')}`
                : ''}
              ）
            </span>
          </div>
        </div>
        <button
          type="button"
          className="btn btn-sm"
          disabled={syncingCatalog}
          onClick={() => void handleSyncModelCatalog()}
          title="从 models.dev / OpenRouter 联网拉取最新旗舰模型上下文与输入输出默认参数（离线时自动保留内置快照）"
        >
          <CloudDownload size={13.5} />
          {syncingCatalog ? '正在拉取最新配置...' : '拉取最新模型默认配置'}
        </button>
      </div>

      {/* One-Click Presets */}
      <div style={{ marginBottom: 10, fontWeight: 620, fontSize: 13.5 }}>
        一键填入主流官方 / 第三方兼容中转 / 本地私有模型预设
      </div>
      <div className="preset-grid">
        {(overview?.presets || []).map((preset) => (
          <button
            key={preset.id}
            type="button"
            className="preset-card"
            onClick={() => applyPreset(preset)}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: 6,
                width: '100%',
              }}
            >
              <strong style={{ fontSize: 13.5, color: 'var(--text-primary)' }}>{preset.name}</strong>
              <span className="tag-chip mono" style={{ fontSize: 10.5 }}>
                {PROTOCOL_LABELS[preset.protocol] || preset.protocol}
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--accent-teal)', wordBreak: 'break-all' }}>
                {preset.default_model}
              </span>
              {preset.context_window ? (
                <span className="mono" style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>
                  窗口 {formatTokensCompact(preset.context_window)} · 输出 {formatTokensCompact(preset.max_output_tokens)}
                </span>
              ) : null}
            </div>
            <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>{preset.description}</span>
          </button>
        ))}
      </div>

      <div className="security-grid">
        {/* Provider Form */}
        <section className="sec-panel">
          <h3>
            <KeyRound size={16} style={{ color: 'var(--accent-teal)' }} />
            {provForm.id
              ? '编辑已保存的大模型配置'
              : provForm.clone_from_id
              ? `基于「${provForm.clone_source_name}」复制为新模型`
              : '接入新大模型供应商'}
          </h3>
          <p className="sec-panel-desc">
            全链路强制 SSE 流式请求；支持 OpenAI (Chat / Responses)、Claude、Gemini 官方及第三方兼容中转，所有参数上限完全开放。API Key 与敏感请求头直接进入加密保险库（XChaCha20-Poly1305）。
          </p>

          {provForm.clone_from_id && (
            <div
              className="alert"
              style={{
                background: 'var(--accent-teal-soft)',
                border: '1px solid var(--accent-teal-border)',
                color: 'var(--accent-teal)',
                marginBottom: 12,
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                gap: 8,
              }}
            >
              <span>
                复用「{provForm.clone_source_name}」同端点的加密 API Key（留空即继承，更换接口地址或协议则需重填）
              </span>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() =>
                  setProvForm((prev) => ({
                    ...prev,
                    clone_from_id: '',
                    clone_source_name: '',
                  }))
                }
              >
                <X size={13} />
              </button>
            </div>
          )}

          {testResultBanner && (
            <div
              className={`alert ${testResultBanner.ok ? '' : 'alert-error'}`}
              style={
                testResultBanner.ok
                  ? {
                      background: 'var(--accent-teal-soft)',
                      border: '1px solid var(--accent-teal-border)',
                      color: 'var(--accent-teal)',
                      marginBottom: 12,
                    }
                  : { marginBottom: 12 }
              }
            >
              <span>{testResultBanner.text}</span>
            </div>
          )}

          <form onSubmit={handleSaveProvider}>
            <div className="field-row">
              <div className="field">
                <label className="field-label">配置显示名称</label>
                <input
                  className="input"
                  value={provForm.name}
                  onChange={(e) => setProvForm({ ...provForm, name: e.target.value })}
                  placeholder="例如：生产 Claude Sonnet 5.5 专线"
                  required
                />
              </div>
              <div className="field">
                <label className="field-label">接口通信协议</label>
                <select
                  className="select"
                  value={provForm.protocol}
                  onChange={(e) =>
                    setProvForm({ ...provForm, protocol: e.target.value as AIProtocol })
                  }
                >
                  <option value="openai">OpenAI Chat Completions 兼容 (/chat/completions)</option>
                  <option value="openai_responses">OpenAI Responses API (/responses · GPT-5/6/Codex)</option>
                  <option value="anthropic">Anthropic Messages 原生/兼容 (/messages)</option>
                  <option value="gemini">Google Gemini 原生/兼容 (:streamGenerateContent)</option>
                </select>
              </div>
            </div>

            <div className="field-row">
              <div className="field" style={{ flex: 2 }}>
                <label className="field-label">API Base URL</label>
                <input
                  className="input mono"
                  value={provForm.base_url}
                  onChange={(e) => setProvForm({ ...provForm, base_url: e.target.value })}
                  placeholder={
                    provForm.protocol === 'gemini'
                      ? 'https://generativelanguage.googleapis.com/v1beta 或第三方中转地址'
                      : provForm.protocol === 'anthropic'
                      ? 'https://api.anthropic.com 或第三方 Claude 中转地址'
                      : 'https://api.openai.com/v1 或第三方 OpenAI 中转地址'
                  }
                  required
                />
              </div>
              <div className="field" style={{ flex: 1 }}>
                <label className="field-label">端点路径策略</label>
                <select
                  className="select"
                  value={provForm.endpoint_mode}
                  onChange={(e) =>
                    setProvForm({ ...provForm, endpoint_mode: e.target.value as AIEndpointMode })
                  }
                >
                  <option value="auto">智能补全协议后缀（推荐）</option>
                  <option value="exact">原样完整地址直连（不拼接）</option>
                </select>
              </div>
            </div>

            <div className="field">
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 8,
                  flexWrap: 'wrap',
                  marginBottom: 4,
                }}
              >
                <label className="field-label" style={{ marginBottom: 0 }}>
                  模型标识 (Model ID)
                </label>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                  {matchedCatalogSpec && (
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm"
                      style={{ height: 24, fontSize: 11.5 }}
                      onClick={() => applyModelEntryDefaults(matchedCatalogSpec, true)}
                      title="按最新模型目录一键回填上下文窗口、最大输入与最大输出默认值"
                    >
                      <Sparkles size={11.5} /> 填入该模型默认参数
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn btn-sm"
                    style={{ height: 24, fontSize: 11.5 }}
                    onClick={() => setShowModelPicker((prev) => !prev)}
                  >
                    <Search size={11.5} /> {showModelPicker ? '收起模型列表' : '选择目录模型'}
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm"
                    style={{ height: 24, fontSize: 11.5 }}
                    disabled={fetchingModels}
                    onClick={() => void handleFetchProviderModels()}
                    title="向当前 Base URL 发起 /models 请求拉取可用模型"
                  >
                    <RefreshCw size={11.5} />
                    {fetchingModels ? '拉取中...' : '拉取接口 /models'}
                  </button>
                </div>
              </div>
              <input
                className="input mono"
                value={provForm.model}
                onChange={(e) => setProvForm({ ...provForm, model: e.target.value })}
                placeholder="例如 gpt-6.2-sol / claude-sonnet-5-5 / gemini-4-neon / deepseek-v4-pro / 任意自定义模型名"
                required
              />

              {showModelPicker && (
                <div className="ai-model-picker-panel">
                  <div className="ai-model-picker-search">
                    <Search size={13} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
                    <input
                      className="input"
                      style={{ border: 'none', background: 'transparent', padding: '4px 0', height: 28 }}
                      value={modelSearch}
                      onChange={(e) => setModelSearch(e.target.value)}
                      placeholder="搜索模型 ID 或厂商（如 gpt-6 / claude / gemini-4 / deepseek / qwen）..."
                    />
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm btn-icon"
                      onClick={() => setShowModelPicker(false)}
                    >
                      <X size={13} />
                    </button>
                  </div>
                  <div className="ai-model-picker-list">
                    {combinedModelOptions.length === 0 ? (
                      <div style={{ padding: '12px', fontSize: 12, color: 'var(--text-muted)', textAlign: 'center' }}>
                        未找到匹配模型，可直接在上方输入框自由填写任意 Model ID
                      </div>
                    ) : (
                      combinedModelOptions.map((m) => (
                        <button
                          key={`${m.source || 'c'}:${m.id}`}
                          type="button"
                          className="ai-model-picker-item"
                          onClick={() => applyModelEntryDefaults(m, true)}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
                            <span className="mono" style={{ fontWeight: 600, fontSize: 12, wordBreak: 'break-all' }}>
                              {m.id}
                            </span>
                            {m.source === 'provider' && (
                              <span className="tag-chip teal" style={{ fontSize: 10, padding: '0 5px' }}>
                                接口实时
                              </span>
                            )}
                            {m.supports_reasoning && (
                              <span className="tag-chip" style={{ fontSize: 10, padding: '0 5px' }}>
                                思考
                              </span>
                            )}
                          </div>
                          <span className="mono" style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0 }}>
                            窗 {formatTokensCompact(m.context_window)} · 入 {formatTokensCompact(m.max_input_tokens)} · 出{' '}
                            {formatTokensCompact(m.max_output_tokens)}
                          </span>
                        </button>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>

            <div className="field">
              <label className="field-label">
                API Key 密钥{' '}
                {provForm.id || provForm.clone_from_id
                  ? '（留空则保留原加密密钥不变）'
                  : '（本地 Ollama 等免密服务可留空）'}
              </label>
              <input
                type="password"
                className="input mono"
                value={provForm.api_key}
                onChange={(e) => setProvForm({ ...provForm, api_key: e.target.value })}
                placeholder={
                  provForm.id || provForm.clone_from_id
                    ? '已加密存储，如需更换请输入新密钥'
                    : 'sk-... / AIza...'
                }
                autoComplete="off"
              />
            </div>

            {/* Unrestricted Token Limits */}
            <div className="field-row field-row-3">
              <div className="field">
                <label className="field-label">上下文窗口 (0=默认)</label>
                <input
                  type="number"
                  className="input mono"
                  min={0}
                  step={1}
                  value={provForm.context_window}
                  onChange={(e) => setProvForm({ ...provForm, context_window: e.target.value })}
                  placeholder="无上限，0=按模型默认"
                />
              </div>
              <div className="field">
                <label className="field-label">最大输入 Tokens (0=默认)</label>
                <input
                  type="number"
                  className="input mono"
                  min={0}
                  step={1}
                  value={provForm.max_input_tokens}
                  onChange={(e) => setProvForm({ ...provForm, max_input_tokens: e.target.value })}
                  placeholder="无上限，0=自动推算"
                />
              </div>
              <div className="field">
                <label className="field-label">单轮最大输出 (0=不限制/默认)</label>
                <input
                  type="number"
                  className="input mono"
                  min={0}
                  step={1}
                  value={provForm.max_output_tokens}
                  onChange={(e) => setProvForm({ ...provForm, max_output_tokens: e.target.value })}
                  placeholder="无上限，0=不显式下发"
                />
              </div>
            </div>

            {/* Collapsible Advanced & Unrestricted Custom Params */}
            <div className="ai-advanced-box">
              <button
                type="button"
                className="ai-advanced-toggle"
                onClick={() => setShowAdvanced((prev) => !prev)}
                aria-expanded={showAdvanced}
              >
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  {showAdvanced ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  <Sliders size={13.5} style={{ color: 'var(--accent-teal)' }} />
                  <strong>高级参数、第三方兼容与自定义扩展（不受限制）</strong>
                </span>
                <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                  思考强度 / 认证头 / 采样 / Custom Headers / Extra Body JSON
                </span>
              </button>

              {showAdvanced && (
                <div className="ai-advanced-body">
                  <div className="field-row">
                    <div className="field">
                      <label className="field-label">思考 / 推理强度 (Reasoning Effort)</label>
                      <select
                        className="select"
                        value={provForm.reasoning_effort}
                        onChange={(e) =>
                          setProvForm({
                            ...provForm,
                            reasoning_effort: e.target.value as AIReasoningEffort,
                          })
                        }
                      >
                        <option value="">跟随模型默认（不强制指定）</option>
                        <option value="off">关闭思考 (off / none / minimal)</option>
                        <option value="low">低 (low · 快速响应)</option>
                        <option value="medium">中 (medium · 均衡)</option>
                        <option value="high">高 (high · 深度排障)</option>
                        <option value="max">最高 (max / xhigh · 复杂根因)</option>
                      </select>
                    </div>
                    <div className="field">
                      <label className="field-label">第三方 API 认证方式 (Auth Mode)</label>
                      <select
                        className="select"
                        value={provForm.auth_mode}
                        onChange={(e) =>
                          setProvForm({ ...provForm, auth_mode: e.target.value as AIAuthMode })
                        }
                      >
                        <option value="auto">按协议自动（OpenAI:Bearer / Claude:x-api-key / Gemini:x-goog-api-key）</option>
                        <option value="bearer">Authorization: Bearer &lt;Key&gt;</option>
                        <option value="x-api-key">x-api-key: &lt;Key&gt;</option>
                        <option value="x-goog-api-key">x-goog-api-key: &lt;Key&gt;</option>
                        <option value="query_key">URL 查询参数 (?key=&lt;Key&gt;)</option>
                        <option value="none">不发送认证头（本地免密或仅靠自定义 Header）</option>
                      </select>
                    </div>
                  </div>

                  <div className="field-row">
                    <div className="field">
                      <label className="field-label">Temperature（留空=不传/跟随模型默认）</label>
                      <input
                        type="number"
                        step="any"
                        className="input mono"
                        value={provForm.temperature}
                        onChange={(e) => setProvForm({ ...provForm, temperature: e.target.value })}
                        placeholder="留空（推理模型建议留空）"
                      />
                    </div>
                    <div className="field">
                      <label className="field-label">Top P（留空=不传/跟随模型默认）</label>
                      <input
                        type="number"
                        step="any"
                        className="input mono"
                        value={provForm.top_p}
                        onChange={(e) => setProvForm({ ...provForm, top_p: e.target.value })}
                        placeholder="留空"
                      />
                    </div>
                  </div>

                  {/* Custom HTTP Headers */}
                  <div className="field">
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        marginBottom: 5,
                      }}
                    >
                      <label className="field-label" style={{ marginBottom: 0 }}>
                        自定义 HTTP 请求头 (Custom Headers · 加密存储，可覆盖任意默认头)
                      </label>
                      <button
                        type="button"
                        className="btn btn-sm"
                        style={{ height: 24, fontSize: 11.5 }}
                        onClick={() =>
                          setProvForm((prev) => ({
                            ...prev,
                            custom_headers: [...prev.custom_headers, { key: '', value: '' }],
                          }))
                        }
                      >
                        <Plus size={11.5} /> 添加请求头
                      </button>
                    </div>
                    {provForm.custom_headers.length === 0 ? (
                      <div style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                        可用于传递中转站自定义头（如 <code className="mono">anthropic-beta</code>、<code className="mono">HTTP-Referer</code>、<code className="mono">X-Title</code> 或额外鉴权头）
                      </div>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {provForm.custom_headers.map((h, idx) => (
                          <div key={idx} className="ai-header-kv-row">
                            <input
                              className="input mono"
                              placeholder="Header 名称，如 anthropic-beta"
                              value={h.key}
                              onChange={(e) => {
                                const cp = [...provForm.custom_headers];
                                cp[idx] = { ...h, key: e.target.value };
                                setProvForm({ ...provForm, custom_headers: cp });
                              }}
                            />
                            <input
                              type={h.isSensitive ? 'password' : 'text'}
                              className="input mono"
                              placeholder={
                                h.isSensitive && h.hasStoredValue
                                  ? `已加密 (${h.valuePreview})，留空保留`
                                  : 'Header 值'
                              }
                              value={h.value}
                              onChange={(e) => {
                                const cp = [...provForm.custom_headers];
                                cp[idx] = { ...h, value: e.target.value };
                                setProvForm({ ...provForm, custom_headers: cp });
                              }}
                            />
                            <button
                              type="button"
                              className="btn btn-ghost btn-sm btn-icon"
                              style={{ color: 'var(--danger-text)' }}
                              onClick={() =>
                                setProvForm((prev) => ({
                                  ...prev,
                                  custom_headers: prev.custom_headers.filter((_, i) => i !== idx),
                                }))
                              }
                              title="移除此请求头"
                            >
                              <Trash2 size={13} />
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Unrestricted Extra Body JSON */}
                  <div className="field" style={{ marginBottom: 0 }}>
                    <label className="field-label">
                      自定义扩展请求体 JSON (Extra Body · 无字段限制，深度合并覆盖最终请求，设字段为 <code className="mono">null</code> 可删除默认参数)
                    </label>
                    <textarea
                      className="input mono"
                      rows={3}
                      style={{ height: 'auto', minHeight: 74, padding: '8px 10px', fontSize: 12 }}
                      value={provForm.extra_body_json}
                      onChange={(e) => setProvForm({ ...provForm, extra_body_json: e.target.value })}
                      placeholder={'例如：{"enable_thinking": true, "thinking_budget": 16384} 或 {"generationConfig": {"topK": 40}}'}
                    />
                    {extraBodyValidationError && (
                      <div style={{ fontSize: 11.5, color: 'var(--danger-text)', marginTop: 4 }}>
                        {extraBodyValidationError}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 12, flexWrap: 'wrap' }}>
              <button type="submit" className="btn btn-primary">
                {provForm.id ? '更新模型配置' : '加密保存并设为激活'}
              </button>
              <button
                type="button"
                className="btn"
                disabled={testingProvId === '__form__'}
                onClick={() => void handleTestProvider()}
              >
                <RefreshCw size={13.5} />
                {testingProvId === '__form__' ? '流式握手自检中...' : '流式连通测试'}
              </button>
              {(provForm.id || provForm.clone_from_id) && (
                <button
                  type="button"
                  className="btn btn-ghost"
                  onClick={() => {
                    setProvForm(makeEmptyForm());
                    setDiscoveredModels([]);
                    setTestResultBanner(null);
                  }}
                >
                  取消编辑
                </button>
              )}
            </div>
          </form>
        </section>

        {/* Saved Providers & Global Active Selector */}
        <section className="sec-panel">
          <h3>
            <Cpu size={16} />
            已加密保存的模型列表 ({overview?.providers?.length || 0})
          </h3>
          <p className="sec-panel-desc">
            采用单全局激活模型路由：排障对话、终端副驾驶与后台异常研判统一以流式方式调用当前激活模型。点击复制图标可复用同端点密钥快速新增其他模型。
          </p>

          {!overview?.providers?.length ? (
            <div style={{ padding: '32px 12px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 12.5 }}>
              暂未保存任何大模型供应商，可点击上方预设卡片快速配置
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, minWidth: 0 }}>
              {overview.providers.map((p) => {
                const isActive = overview.active_provider_id === p.id;
                const maxOut = p.max_output_tokens ?? p.max_tokens ?? 0;
                return (
                  <div
                    key={p.id}
                    style={{
                      padding: '12px 14px',
                      borderRadius: 8,
                      border: `1px solid ${
                        isActive ? 'var(--accent-teal-border)' : 'var(--border-default)'
                      }`,
                      background: isActive ? 'var(--accent-teal-soft)' : 'var(--bg-subtle)',
                      minWidth: 0,
                      maxWidth: '100%',
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        gap: 8,
                        flexWrap: 'wrap',
                        minWidth: 0,
                        maxWidth: '100%',
                      }}
                    >
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 6,
                          flexWrap: 'wrap',
                          minWidth: 0,
                          maxWidth: '100%',
                        }}
                      >
                        <strong
                          style={{
                            minWidth: 0,
                            maxWidth: '100%',
                            overflowWrap: 'anywhere',
                            wordBreak: 'break-word',
                          }}
                        >
                          {p.name}
                        </strong>
                        <span
                          className="tag-chip mono"
                          style={{
                            display: 'inline-block',
                            maxWidth: '100%',
                            minWidth: 0,
                            flexShrink: 1,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                          title={p.model}
                        >
                          {p.model}
                        </span>
                        {isActive && <span className="tag-chip teal">当前全局激活</span>}
                        {p.reasoning_effort && (
                          <span className="tag-chip" style={{ fontSize: 10.5 }}>
                            思考: {REASONING_LABELS[p.reasoning_effort] || p.reasoning_effort}
                          </span>
                        )}
                      </div>
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 4,
                          flexWrap: 'wrap',
                          minWidth: 0,
                          maxWidth: '100%',
                        }}
                      >
                        {!isActive && (
                          <button
                            type="button"
                            className="btn btn-teal btn-sm"
                            onClick={async () => {
                              try {
                                await api.setActiveAIProvider(p.id);
                                onNotify(`已切换全局激活模型为 ${p.name}`);
                                await onReloadOverview();
                              } catch (err: any) {
                                onNotify(err?.message || '切换激活模型失败');
                              }
                            }}
                          >
                            设为激活
                          </button>
                        )}
                        <button
                          type="button"
                          className="btn btn-sm"
                          disabled={testingProvId === p.id}
                          onClick={() => void handleTestProvider(p)}
                        >
                          {testingProvId === p.id ? '测试中...' : '测速'}
                        </button>
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm btn-icon"
                          onClick={() => cloneExistingProvider(p)}
                          title="复制为新模型（同端点复用已加密 API Key）"
                        >
                          <Copy size={13.5} />
                        </button>
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm btn-icon"
                          onClick={() => editExistingProvider(p)}
                          title="编辑配置"
                        >
                          <Edit3 size={13.5} />
                        </button>
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm btn-icon"
                          style={{ color: 'var(--danger-text)' }}
                          onClick={async () => {
                            try {
                              await api.deleteAIProvider(p.id);
                              onNotify('已删除模型供应商配置');
                              await onReloadOverview();
                            } catch (err: any) {
                              onNotify(err?.message || '删除模型供应商失败');
                            }
                          }}
                          title="删除"
                        >
                          <Trash2 size={13.5} />
                        </button>
                      </div>
                    </div>
                    <div className="mono provider-meta-row">
                      <span style={{ minWidth: 0, maxWidth: '100%', overflowWrap: 'anywhere', wordBreak: 'break-word' }}>
                        [{PROTOCOL_LABELS[p.protocol] || p.protocol}]
                        {p.endpoint_mode === 'exact' ? ' [直连]' : ''} {p.base_url}
                      </span>
                      <span style={{ minWidth: 0, maxWidth: '100%', overflowWrap: 'anywhere', wordBreak: 'break-word' }}>
                        密钥: {p.has_api_key ? p.api_key_preview : '未设置(免密)'}
                        {p.auth_mode && p.auth_mode !== 'auto' ? ` (${p.auth_mode})` : ''}
                        {` · 窗口:${formatTokensCompact(p.context_window)} · 输入:${formatTokensCompact(p.max_input_tokens)} · 输出:${formatTokensCompact(maxOut)}`}
                        {p.custom_headers?.length ? ` · +${p.custom_headers.length}头` : ''}
                        {p.extra_body_json ? ' · 自定义Body' : ''}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
