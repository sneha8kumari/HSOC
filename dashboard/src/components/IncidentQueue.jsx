import React, { useState, useMemo } from 'react';
import { Search, Filter, ShieldAlert, Check } from 'lucide-react';
import { getHumanReadableTitle, getAffectedAsset, getTimeAgo, SEVERITY_CONFIG } from '../utils/incidentHelpers';
import { QueueSkeleton } from './SkeletonLoader';

export default function IncidentQueue({
  incidents = [],
  selectedIncidentId,
  onSelectIncident,
  loading = false,
  liveIncidentId = null,
  telemetryFilter = 'all',
  onOpenShortcuts,
}) {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');

  // Filter and sort incidents: default severity rank descending, then risk score descending
  const filteredIncidents = useMemo(() => {
    return incidents
      .filter((inc) => {
        if (severityFilter !== 'all' && inc.severity !== severityFilter) return false;
        if (statusFilter !== 'all' && inc.status !== statusFilter) return false;
        if (telemetryFilter === 'live' && inc.is_simulated) return false;
        if (telemetryFilter === 'simulated' && !inc.is_simulated) return false;
        if (search.trim()) {
          const q = search.toLowerCase();
          const title = getHumanReadableTitle(inc).toLowerCase();
          const asset = getAffectedAsset(inc).toLowerCase();
          const id = (inc.incident_id || '').toLowerCase();
          return title.includes(q) || asset.includes(q) || id.includes(q);
        }
        return true;
      })
      .sort((a, b) => {
        const rankA = SEVERITY_CONFIG[a.severity]?.rank || 0;
        const rankB = SEVERITY_CONFIG[b.severity]?.rank || 0;
        if (rankB !== rankA) return rankB - rankA;
        return (b.risk_score || 0) - (a.risk_score || 0);
      });
  }, [incidents, severityFilter, statusFilter, search]);

  return (
    <aside
      aria-label="Incident triage panel"
      style={{
        width: '340px',
        minWidth: '300px',
        maxWidth: '380px',
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        backgroundColor: 'var(--surface-panel)',
        borderRight: '1px solid var(--border-default)',
      }}
    >
      {/* ── Queue Header & Counters ── */}
      <div
        style={{
          padding: '12px 14px',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          flexDirection: 'column',
          gap: '10px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)' }}>
              Open incidents
            </span>
            <span
              className="font-mono"
              aria-live="polite"
              aria-atomic="true"
              style={{
                fontSize: '11px',
                color: 'var(--text-muted)',
                backgroundColor: 'var(--surface-subtle)',
                padding: '1px 6px',
                borderRadius: 'var(--radius-sm)',
              }}
            >
              {loading ? '...' : filteredIncidents.length}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Sort:</span>
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 500 }}>
              Severity
            </span>
          </div>
        </div>

        {/* ── Search Input ── */}
        <div style={{ position: 'relative' }}>
          <Search
            size={13}
            aria-hidden="true"
            style={{
              position: 'absolute',
              left: '9px',
              top: '50%',
              transform: 'translateY(-50%)',
              color: 'var(--text-muted)',
            }}
          />
          <input
            type="text"
            className="input-text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by title, host, IP or ID..."
            aria-label="Filter incidents by title, host, IP or ID"
            style={{
              width: '100%',
              paddingLeft: '28px',
              paddingTop: '5px',
              paddingBottom: '5px',
              fontSize: '12px',
            }}
          />
        </div>

        {/* ── Severity Filter Buttons ── */}
        <div role="group" aria-label="Filter incidents by severity" style={{ display: 'flex', gap: '4px' }}>
          {['all', 'critical', 'high', 'medium', 'low'].map((sev) => {
            const isSelected = severityFilter === sev;
            const cfg = SEVERITY_CONFIG[sev];
            return (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                aria-pressed={isSelected}
                aria-label={`Filter by severity ${sev}`}
                style={{
                  flex: 1,
                  padding: '3px 0',
                  fontSize: '11px',
                  fontWeight: isSelected ? 600 : 400,
                  backgroundColor: isSelected ? 'var(--surface-active)' : 'transparent',
                  color: isSelected ? (cfg ? cfg.text : 'var(--text-primary)') : 'var(--text-muted)',
                  border: isSelected ? '1px solid var(--border-strong)' : '1px solid transparent',
                  borderRadius: 'var(--radius-sm)',
                  cursor: 'pointer',
                  textTransform: 'capitalize',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '3px',
                }}
              >
                {cfg && <span style={{ fontSize: '8px' }}>{cfg.symbol}</span>}
                {sev === 'all' ? 'All' : sev.slice(0, 4)}
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Incident Rows List (Supports Loading Skeleton) ── */}
      <div
        role="feed"
        aria-label="Incident Queue"
        style={{
          flex: 1,
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        {loading ? (
          <QueueSkeleton count={6} />
        ) : filteredIncidents.length === 0 ? (
          <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-muted)' }}>
            <p style={{ fontSize: '13px' }}>No matching incidents found</p>
            <p style={{ fontSize: '11px', marginTop: '4px' }}>Try clearing filters or search term</p>
          </div>
        ) : (
          filteredIncidents.map((inc) => {
            const isSelected = inc.incident_id === selectedIncidentId;
            const sev = SEVERITY_CONFIG[inc.severity] || SEVERITY_CONFIG.medium;
            const title = getHumanReadableTitle(inc);
            const asset = getAffectedAsset(inc);
            const timeAgo = getTimeAgo(inc.updated_at || inc.created_at);

            const tacticWord = inc.tactics && inc.tactics.length > 0 ? inc.tactics[0].replace(/_/g, ' ') : null;

            return (
              <div
                key={inc.incident_id}
                role="article"
                aria-selected={isSelected}
                tabIndex={0}
                className="queue-row"
                onClick={() => onSelectIncident(inc.incident_id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onSelectIncident(inc.incident_id);
                  }
                }}
                style={{
                  position: 'relative',
                  padding: 'var(--density-queue-pad, 9px 12px 9px 14px)',
                  cursor: 'pointer',
                  backgroundColor: isSelected ? 'var(--surface-selected)' : 'transparent',
                  borderBottom: '1px solid var(--border-subtle)',
                  borderLeft: isSelected ? `3px solid ${sev.color}` : '3px solid transparent',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 'var(--density-queue-gap, 3px)',
                  transition: 'background-color 0.1s ease',
                }}
                onMouseEnter={(e) => {
                  if (!isSelected) e.currentTarget.style.backgroundColor = 'var(--surface-hover)';
                }}
                onMouseLeave={(e) => {
                  if (!isSelected) e.currentTarget.style.backgroundColor = 'transparent';
                }}
              >
                {/* Line 1: Title and Risk score */}
                <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: '8px' }}>
                  <div
                    style={{
                      fontSize: 'var(--density-title-size, 12.5px)',
                      fontWeight: isSelected ? 600 : 500,
                      color: 'var(--text-primary)',
                      lineHeight: '1.3',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      flex: 1,
                    }}
                    title={title}
                  >
                    {title}
                  </div>

                  <div
                    className="font-mono"
                    style={{
                      fontSize: '11.5px',
                      fontWeight: 600,
                      color: inc.risk_score >= 70 ? 'var(--severity-critical-text)' : inc.risk_score >= 50 ? 'var(--severity-high-text)' : 'var(--text-secondary)',
                      flexShrink: 0,
                    }}
                    title={`Risk score: ${inc.risk_score}`}
                  >
                    {inc.risk_score}
                  </div>
                </div>

                {/* Line 2: Asset, Tactic as plain words, Time */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 'var(--density-meta-size, 11px)', color: 'var(--text-muted)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', overflow: 'hidden' }}>
                    <span style={{ color: sev.text, fontWeight: 600, fontSize: '9px' }}>
                      {sev.symbol}
                    </span>
                    <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                      {asset}
                    </span>
                    {tacticWord && (
                      <>
                        <span style={{ color: 'var(--border-strong)' }}>·</span>
                        <span style={{ textTransform: 'capitalize', color: 'var(--text-secondary)' }}>
                          {tacticWord}
                        </span>
                      </>
                    )}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '5px', flexShrink: 0, marginLeft: '6px' }}>
                    {inc.is_simulated ? (
                      <span
                        style={{
                          backgroundColor: 'var(--surface-active)',
                          color: 'var(--text-muted)',
                          fontSize: '8.5px',
                          fontWeight: 600,
                          padding: '0 4px',
                          borderRadius: '2px',
                          border: '1px solid var(--border-default)',
                        }}
                        title="Simulated demo scenario"
                      >
                        DEMO
                      </span>
                    ) : (
                      <span
                        style={{
                          backgroundColor: 'var(--state-success-bg)',
                          color: 'var(--state-success-text)',
                          fontSize: '8.5px',
                          fontWeight: 600,
                          padding: '0 4px',
                          borderRadius: '2px',
                          border: '1px solid var(--state-success)',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '2px',
                        }}
                        title="Real telemetry from host or Wazuh"
                      >
                        <span style={{ width: '4px', height: '4px', borderRadius: '50%', backgroundColor: 'var(--state-success)' }} />
                        HOST
                      </span>
                    )}

                    {liveIncidentId === inc.incident_id && (
                      <span
                        style={{
                          backgroundColor: 'var(--severity-high-bg)',
                          color: 'var(--severity-high-text)',
                          fontSize: '8.5px',
                          fontWeight: 600,
                          padding: '0 4px',
                          borderRadius: '2px',
                        }}
                      >
                        STREAM
                      </span>
                    )}
                    <span>{timeAgo}</span>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* ── Footer Keyboard Tips ── */}
      <div
        style={{
          padding: '8px 12px',
          borderTop: '1px solid var(--border-subtle)',
          fontSize: '10.5px',
          color: 'var(--text-muted)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ display: 'flex', gap: '8px' }}>
          <span><kbd style={{ fontFamily: 'var(--font-mono)', padding: '1px 4px', background: 'var(--surface-subtle)', borderRadius: '2px' }}>j</kbd>/<kbd style={{ fontFamily: 'var(--font-mono)', padding: '1px 4px', background: 'var(--surface-subtle)', borderRadius: '2px' }}>k</kbd></span>
          <span><kbd style={{ fontFamily: 'var(--font-mono)', padding: '1px 4px', background: 'var(--surface-subtle)', borderRadius: '2px' }}>Enter</kbd></span>
        </div>
        {onOpenShortcuts && (
          <button
            onClick={onOpenShortcuts}
            title="Open keyboard shortcuts (?)"
            aria-label="Open keyboard shortcuts cheat sheet"
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-muted)',
              fontSize: '10.5px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
            }}
          >
            <kbd style={{ fontFamily: 'var(--font-mono)', padding: '1px 5px', background: 'var(--surface-subtle)', borderRadius: '2px', color: 'var(--text-secondary)' }}>?</kbd>
            <span>Shortcuts</span>
          </button>
        )}
      </div>
    </aside>
  );
}
