import React, { useEffect, useMemo, useRef, useState } from 'react';
import type { MonitorHealthLevel, MonitorSamplePoint } from '../types';

export type MetricUnitType = 'percent' | 'bps' | 'ms' | 'load' | 'count' | 'temp';

export interface ChartSeriesSpec {
  key: string;
  label: string;
  color: string;
  fillOpacity?: number;
  dashed?: boolean;
  accessor: (pt: MonitorSamplePoint) => number;
}

export function formatBytesRate(bps: number | undefined | null): string {
  const val = Math.max(0, Number(bps || 0));
  if (val < 1024) return `${Math.round(val)} B/s`;
  if (val < 1024 * 1024) return `${(val / 1024).toFixed(1)} KB/s`;
  if (val < 1024 * 1024 * 1024) return `${(val / (1024 * 1024)).toFixed(2)} MB/s`;
  return `${(val / (1024 * 1024 * 1024)).toFixed(2)} GB/s`;
}

export function formatBytesTotal(bytes: number | undefined | null): string {
  const val = Math.max(0, Number(bytes || 0));
  if (val < 1024) return `${Math.round(val)} B`;
  if (val < 1024 * 1024) return `${(val / 1024).toFixed(1)} KB`;
  if (val < 1024 * 1024 * 1024) return `${(val / (1024 * 1024)).toFixed(1)} MB`;
  if (val < 1024 * 1024 * 1024 * 1024) return `${(val / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  return `${(val / (1024 * 1024 * 1024 * 1024)).toFixed(2)} TB`;
}

export function formatMetricValue(val: number, unit: MetricUnitType): string {
  if (!Number.isFinite(val)) return '0';
  switch (unit) {
    case 'percent':
      return `${val.toFixed(1)}%`;
    case 'bps':
      return formatBytesRate(val);
    case 'ms':
      return `${Math.round(val)} ms`;
    case 'load':
      return val.toFixed(2);
    case 'temp':
      return `${val.toFixed(1)}°C`;
    case 'count':
    default:
      return `${Math.round(val)}`;
  }
}

export function formatTimeShort(iso?: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleTimeString('zh-CN', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function formatDateTime(iso?: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString('zh-CN', {
    hour12: false,
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function niceUpperBound(rawMax: number, unit: MetricUnitType): number {
  if (unit === 'percent') {
    if (rawMax <= 25) return 25;
    if (rawMax <= 50) return 50;
    return 100;
  }
  if (rawMax <= 0) {
    if (unit === 'bps') return 1024 * 100;
    if (unit === 'ms') return 100;
    if (unit === 'load') return 2;
    return 10;
  }
  const padded = rawMax * 1.15;
  const mag = Math.pow(10, Math.floor(Math.log10(padded)));
  const norm = padded / mag;
  let step = 10;
  if (norm <= 1.2) step = 1.2;
  else if (norm <= 1.5) step = 1.5;
  else if (norm <= 2) step = 2;
  else if (norm <= 2.5) step = 2.5;
  else if (norm <= 5) step = 5;
  else if (norm <= 8) step = 8;
  return step * mag;
}

export const HealthScoreGauge: React.FC<{
  score: number;
  level: MonitorHealthLevel;
  size?: number;
}> = ({ score, level, size = 46 }) => {
  const stroke = 4;
  const radius = (size - stroke) / 2;
  const circ = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, score || 0));
  const offset = circ - (clamped / 100) * circ;

  const ringColor =
    level === 'healthy'
      ? 'var(--status-online)'
      : level === 'warning'
      ? 'var(--amber-text)'
      : level === 'critical' || level === 'offline'
      ? 'var(--danger-text)'
      : 'var(--text-faint)';

  return (
    <div
      className="mon-score-gauge"
      style={{ width: size, height: size }}
      title={`综合健康评分: ${level === 'offline' ? '离线' : clamped}`}
    >
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--border-default)"
          strokeWidth={stroke}
        />
        {level !== 'unknown' && (
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={ringColor}
            strokeWidth={stroke}
            strokeDasharray={circ}
            strokeDashoffset={level === 'offline' ? circ * 0.88 : offset}
            strokeLinecap="round"
            transform={`rotate(-90 ${size / 2} ${size / 2})`}
          />
        )}
      </svg>
      <span className="mon-score-text tabular" style={{ color: ringColor }}>
        {level === 'offline' ? 'OFF' : level === 'unknown' ? '—' : clamped}
      </span>
    </div>
  );
};

export const MiniSparkline: React.FC<{
  points: MonitorSamplePoint[];
  accessor?: (pt: MonitorSamplePoint) => number;
  color?: string;
  height?: number;
  fixedMax?: number;
}> = ({
  points,
  accessor = (pt) => pt.cpu,
  color = '#0d9488',
  height = 34,
  fixedMax,
}) => {
  const width = 180;
  const padY = 3;

  const { linePath, areaPath, offlineXs } = useMemo(() => {
    if (!points || points.length === 0) {
      return { linePath: '', areaPath: '', offlineXs: [] as number[] };
    }
    const vals = points.map((p) => (p.ok ? Math.max(0, accessor(p)) : 0));
    const maxV = fixedMax || Math.max(10, ...vals) * 1.1;
    const stepX = points.length > 1 ? width / (points.length - 1) : width;

    const coords = vals.map((v, i) => {
      const x = points.length === 1 ? width / 2 : i * stepX;
      const y = height - padY - (Math.min(v, maxV) / maxV) * (height - padY * 2);
      return { x, y, ok: points[i].ok };
    });

    const d = coords
      .map((c, idx) => `${idx === 0 ? 'M' : 'L'}${c.x.toFixed(1)},${c.y.toFixed(1)}`)
      .join(' ');
    const area =
      coords.length > 1
        ? `${d} L${coords[coords.length - 1].x.toFixed(1)},${height} L${coords[0].x.toFixed(1)},${height} Z`
        : '';
    const offs = coords.filter((c) => !c.ok).map((c) => c.x);

    return { linePath: d, areaPath: area, offlineXs: offs };
  }, [points, accessor, fixedMax, height]);

  if (!points || points.length === 0) {
    return <div className="mon-sparkline-empty">暂无时序样本</div>;
  }

  return (
    <svg
      className="mon-sparkline-svg"
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      style={{ height }}
    >
      {areaPath && <path d={areaPath} fill={color} fillOpacity={0.11} />}
      {linePath && (
        <path
          d={linePath}
          fill="none"
          stroke={color}
          strokeWidth={1.6}
          vectorEffect="non-scaling-stroke"
        />
      )}
      {offlineXs.map((x, idx) => (
        <line
          key={idx}
          x1={x}
          y1={0}
          x2={x}
          y2={height}
          stroke="var(--danger-text)"
          strokeOpacity={0.45}
          strokeWidth={2}
          vectorEffect="non-scaling-stroke"
        />
      ))}
    </svg>
  );
};

export const TimeSeriesChart: React.FC<{
  title: string;
  subtitle?: string;
  points: MonitorSamplePoint[];
  series: ChartSeriesSpec[];
  unit: MetricUnitType;
  fixedMax?: number;
  height?: number;
}> = ({ title, subtitle, points, series, unit, fixedMax, height = 186 }) => {
  const stageRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const [compact, setCompact] = useState<boolean>(() =>
    typeof window !== 'undefined' ? window.innerWidth <= 480 : false
  );

  useEffect(() => {
    const el = stageRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width || el.clientWidth;
      if (w > 0) {
        setCompact(w < 430);
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [points.length]);

  useEffect(() => {
    if (hoverIdx === null) return;
    const onDocTouch = (ev: TouchEvent) => {
      if (stageRef.current && !stageRef.current.contains(ev.target as Node)) {
        setHoverIdx(null);
      }
    };
    document.addEventListener('touchstart', onDocTouch, { passive: true });
    return () => document.removeEventListener('touchstart', onDocTouch);
  }, [hoverIdx]);

  const viewW = compact ? 360 : 580;
  const viewH = compact ? Math.min(height, 168) : height;
  const padL = compact ? 58 : 74;
  const padR = compact ? 10 : 14;
  const padT = 10;
  const padB = 22;
  const plotW = viewW - padL - padR;
  const plotH = viewH - padT - padB;

  const computed = useMemo(() => {
    let rawMax = 0;
    const stats = series.map((s) => {
      let sum = 0;
      let cnt = 0;
      let maxV = 0;
      let lastV = 0;
      for (const pt of points) {
        if (!pt.ok) continue;
        const v = Math.max(0, s.accessor(pt) || 0);
        sum += v;
        cnt++;
        if (v > maxV) maxV = v;
        if (v > rawMax) rawMax = v;
        lastV = v;
      }
      return {
        key: s.key,
        last: lastV,
        avg: cnt > 0 ? sum / cnt : 0,
        max: maxV,
      };
    });

    const maxY = fixedMax ?? niceUpperBound(rawMax, unit);
    const xFor = (i: number) =>
      points.length <= 1 ? padL + plotW / 2 : padL + (i / (points.length - 1)) * plotW;
    const yFor = (v: number) =>
      padT + plotH - (Math.min(Math.max(0, v), maxY) / (maxY || 1)) * plotH;

    const paths = series.map((s) => {
      if (points.length === 0) return { spec: s, d: '', area: '' };
      const pts = points.map((pt, idx) => ({
        x: xFor(idx),
        y: yFor(pt.ok ? s.accessor(pt) || 0 : 0),
      }));
      const d = pts
        .map((c, idx) => `${idx === 0 ? 'M' : 'L'}${c.x.toFixed(1)},${c.y.toFixed(1)}`)
        .join(' ');
      const area =
        s.fillOpacity && pts.length > 1
          ? `${d} L${pts[pts.length - 1].x.toFixed(1)},${(padT + plotH).toFixed(1)} L${pts[0].x.toFixed(1)},${(padT + plotH).toFixed(1)} Z`
          : '';
      return { spec: s, d, area };
    });

    const offlineBands: { x: number; w: number }[] = [];
    if (points.length > 0) {
      const stepW = points.length > 1 ? plotW / (points.length - 1) : plotW;
      points.forEach((pt, idx) => {
        if (!pt.ok) {
          offlineBands.push({
            x: Math.max(padL, xFor(idx) - stepW / 2),
            w: Math.max(3, stepW),
          });
        }
      });
    }

    return { maxY, stats, paths, offlineBands, xFor, yFor };
  }, [points, series, fixedMax, unit, padL, plotW, plotH]);

  const updateHoverByClientX = (clientX: number, clampToBounds = false) => {
    if (!svgRef.current || points.length === 0) return;
    const rect = svgRef.current.getBoundingClientRect();
    if (rect.width <= 0) return;
    if (!clampToBounds && (clientX < rect.left || clientX > rect.right)) {
      setHoverIdx(null);
      return;
    }
    const rawRelX = ((clientX - rect.left) / rect.width) * viewW;
    const relX = Math.max(padL, Math.min(viewW - padR, rawRelX));
    if (points.length === 1) {
      setHoverIdx(0);
      return;
    }
    const ratio = Math.max(0, Math.min(1, (relX - padL) / plotW));
    setHoverIdx(Math.round(ratio * (points.length - 1)));
  };

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    updateHoverByClientX(e.clientX, false);
  };

  const handleTouchScrub = (e: React.TouchEvent<SVGSVGElement>) => {
    const touch = e.touches[0];
    if (touch) {
      updateHoverByClientX(touch.clientX, true);
    }
  };

  const activePoint = hoverIdx !== null && points[hoverIdx] ? points[hoverIdx] : null;
  const activeX = hoverIdx !== null ? computed.xFor(hoverIdx) : 0;

  return (
    <section className="mon-chart-card">
      <div className="mon-chart-header">
        <div>
          <h4 className="mon-chart-title">{title}</h4>
          {subtitle && <span className="mon-chart-sub">{subtitle}</span>}
        </div>
        <div className="mon-chart-legend">
          {series.map((s, idx) => {
            const st = computed.stats[idx];
            return (
              <div key={s.key} className="mon-legend-item">
                <span className="mon-legend-dot" style={{ background: s.color }} />
                <span className="mon-legend-name">{s.label}</span>
                <strong className="tabular">{formatMetricValue(st.last, unit)}</strong>
                <span className="mon-legend-peak tabular">
                  峰 {formatMetricValue(st.max, unit)}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {points.length === 0 ? (
        <div className="mon-chart-empty" style={{ height: viewH }}>
          尚无历史采样点，点击「立即采集」或等待定时巡检自动记录
        </div>
      ) : (
        <div className="mon-chart-stage" ref={stageRef}>
          <svg
            ref={svgRef}
            viewBox={`0 0 ${viewW} ${viewH}`}
            className="mon-chart-svg"
            style={{ touchAction: 'pan-y' }}
            onMouseMove={handleMouseMove}
            onMouseLeave={() => setHoverIdx(null)}
            onTouchStart={handleTouchScrub}
            onTouchMove={handleTouchScrub}
          >
            {/* Horizontal gridlines & Y ticks */}
            {[0, 0.5, 1].map((frac) => {
              const y = padT + plotH * (1 - frac);
              const labelVal = computed.maxY * frac;
              return (
                <g key={frac}>
                  <line
                    x1={padL}
                    y1={y}
                    x2={viewW - padR}
                    y2={y}
                    stroke="var(--border-default)"
                    strokeDasharray={frac === 0 ? undefined : '3 3'}
                    strokeWidth={1}
                  />
                  <text
                    x={padL - 6}
                    y={y + 3.5}
                    textAnchor="end"
                    fill="var(--text-muted)"
                    fontSize={compact ? 9.5 : 10}
                    fontFamily="var(--font-mono)"
                  >
                    {formatMetricValue(labelVal, unit)}
                  </text>
                </g>
              );
            })}

            {/* Offline outage shading */}
            {computed.offlineBands.map((b, idx) => (
              <rect
                key={idx}
                x={b.x}
                y={padT}
                width={b.w}
                height={plotH}
                fill="var(--danger-soft)"
              />
            ))}

            {/* Series fills & lines */}
            {computed.paths.map(({ spec, d, area }) => (
              <g key={spec.key}>
                {area && (
                  <path d={area} fill={spec.color} fillOpacity={spec.fillOpacity || 0.1} />
                )}
                {d && (
                  <path
                    d={d}
                    fill="none"
                    stroke={spec.color}
                    strokeWidth={1.85}
                    strokeDasharray={spec.dashed ? '4 3' : undefined}
                    strokeLinejoin="round"
                    strokeLinecap="round"
                  />
                )}
              </g>
            ))}

            {/* Single-point markers when only 1 sample exists */}
            {points.length === 1 &&
              series.map((s) => {
                const cy = computed.yFor(points[0].ok ? s.accessor(points[0]) || 0 : 0);
                return (
                  <circle
                    key={s.key}
                    cx={computed.xFor(0)}
                    cy={cy}
                    r={3.5}
                    fill={s.color}
                  />
                );
              })}

            {/* X-axis timestamps */}
            <text
              x={padL}
              y={viewH - 5}
              textAnchor="start"
              fill="var(--text-muted)"
              fontSize={compact ? 9.5 : 10}
              fontFamily="var(--font-mono)"
            >
              {formatTimeShort(points[0]?.ts)}
            </text>
            {points.length > 2 && (
              <text
                x={padL + plotW / 2}
                y={viewH - 5}
                textAnchor="middle"
                fill="var(--text-muted)"
                fontSize={compact ? 9.5 : 10}
                fontFamily="var(--font-mono)"
              >
                {formatTimeShort(points[Math.floor(points.length / 2)]?.ts)}
              </text>
            )}
            {points.length > 1 && (
              <text
                x={viewW - padR}
                y={viewH - 5}
                textAnchor="end"
                fill="var(--text-muted)"
                fontSize={compact ? 9.5 : 10}
                fontFamily="var(--font-mono)"
              >
                {formatTimeShort(points[points.length - 1]?.ts)}
              </text>
            )}

            {/* Hover Crosshair & Dots */}
            {activePoint && hoverIdx !== null && (
              <g>
                <line
                  x1={activeX}
                  y1={padT}
                  x2={activeX}
                  y2={padT + plotH}
                  stroke="var(--text-secondary)"
                  strokeWidth={1}
                  strokeDasharray="2 2"
                />
                {series.map((s) => {
                  const val = activePoint.ok ? s.accessor(activePoint) || 0 : 0;
                  return (
                    <circle
                      key={s.key}
                      cx={activeX}
                      cy={computed.yFor(val)}
                      r={3.5}
                      fill={s.color}
                      stroke="var(--bg-surface)"
                      strokeWidth={1.5}
                    />
                  );
                })}
              </g>
            )}
          </svg>

          {activePoint && hoverIdx !== null && (
            <div
              className="mon-chart-tooltip"
              style={{
                maxWidth: 'calc(100% - 12px)',
                left: compact
                  ? activeX > viewW * 0.5
                    ? 'auto'
                    : 6
                  : activeX > viewW * 0.62
                  ? 'auto'
                  : `${(activeX / viewW) * 100}%`,
                right: compact
                  ? activeX > viewW * 0.5
                    ? 6
                    : 'auto'
                  : activeX > viewW * 0.62
                  ? `${((viewW - activeX) / viewW) * 100}%`
                  : 'auto',
              }}
            >
              <div className="mon-tooltip-time mono">{formatDateTime(activePoint.ts)}</div>
              {!activePoint.ok ? (
                <div style={{ color: 'var(--danger-text)', fontWeight: 600 }}>节点离线不可达</div>
              ) : (
                series.map((s) => (
                  <div key={s.key} className="mon-tooltip-row">
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                      <span className="mon-legend-dot" style={{ background: s.color }} />
                      {s.label}
                    </span>
                    <strong className="tabular">
                      {formatMetricValue(s.accessor(activePoint) || 0, unit)}
                    </strong>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
};
