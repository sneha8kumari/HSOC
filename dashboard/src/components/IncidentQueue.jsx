import React, { useState, useMemo } from 'react';
import { Search, ShieldAlert, Check } from 'lucide-react';
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
  }, [incidents, severityFilter, statusFilter, search, telemetryFilter]);

  const getSeverityGlow = (sev) => {
    switch (sev) {
      case 'critical':
        return {
          border: '1px solid rgba(244, 63, 94, 0.45)',
          leftBorder: '4px solid #f43f5e',
          badgeBg: 'rgba(244, 63, 94, 0.2)',
          badgeText: '#ff8899',
          scoreBg: 'rgba(244, 63, 94, 0.25)',
          scoreText: '#fda4af',
        };
      case 'high':
        return {
          border: '1px solid rgba(249, 115, 22, 0.4)',
          leftBorder: '4px solid #f97316',
          badgeBg: 'rgba(249, 115, 22, 0.2)',
          badgeText: '#fb923c',
          scoreBg: 'rgba(249, 115, 22, 0.25)',
          scoreText: '#fed7aa',
        };
      case 'medium':
        return {
          border: '1px solid rgba(234, 179, 8, 0.35)',
          leftBorder: '4px solid #eab308',
          badgeBg: 'rgba(234, 179, 8, 0.2)',
          badgeText: '#fde047',
          scoreBg: 'rgba(234, 179, 8, 0.2)',
          scoreText: '#fef08a',
        };
      case 'low':
      default:
        return {
          border: '1px solid rgba(16, 185, 129, 0.35)',
          leftBorder: '4px solid #10b981',
          badgeBg: 'rgba(16, 185, 129, 0.2)',
          badgeText: '#34d399',
          scoreBg: 'rgba(16, 185, 129, 0.2)',
          scoreText: '#a7f3d0',
        };
    }
  };

  return (
    <aside
      aria-label="Incident triage panel"
      style={{
        width: '360px',
        minWidth: '320px',
        maxWidth: '400px',
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        backgroundColor: 'var(--surface-panel)',
        borderRight: '1px solid var(--border-default)',
      }}
    >
      {/* ── Queue Header & Search ── */}
      <div
        style={{
          padding: '14px 16px',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          flexDirection: 'column',
          gap: '12px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontWeight: 700, fontSize: '13.5px', color: 'var(--text-primary)', letterSpacing: '0.3px' }}>
              INCIDENT QUEUE
            </span>
            <span
              className="font-mono"
              style={{
                fontSize: '11px',
                fontWeight: 600,
                color: '#38bdf8',
                backgroundColor: 'rgba(56, 189, 248, 0.15)',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                padding: '2px 7px',
                borderRadius: '10px',
              }}
            >
              {loading ? '...' : filteredIncidents.length}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '11px', color: 'var(--text-muted)' }}>
            <span>Rank:</span>
            <span style={{ color: '#38bdf8', fontWeight: 600 }}>Risk Score</span>
          </div>
        </div>

        {/* ── Search Input ── */}
        <div style={{ position: 'relative' }}>
          <Search
            size={14}
            style={{
              position: 'absolute',
              left: '10px',
              top: '50%',
              transform: 'translateY(-50%)',
              color: '#64748b',
            }}
          />
          <input
            type="text"
            className="input-text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search host, IP, attack type..."
            style={{
              width: '100%',
              paddingLeft: '32px',
              paddingTop: '7px',
              paddingBottom: '7px',
              fontSize: '12px',
              backgroundColor: 'rgba(15, 23, 42, 0.7)',
            }}
          />
        </div>

        {/* ── Severity Filter Buttons ── */}
        <div role="group" aria-label="Filter incidents by severity" style={{ display: 'flex', gap: '4px' }}>
          {['all', 'critical', 'high', 'medium', 'low'].map((sev) => {
            const isSelected = severityFilter === sev;
            const cfg = SEVERITY_CONFIG[sev];
            let activeColor = '#00f0ff';
            let activeBg = 'rgba(0, 240, 255, 0.15)';
            if (sev === 'critical') { activeColor = '#f43f5e'; activeBg = 'rgba(244, 63, 94, 0.2)'; }
            else if (sev === 'high') { activeColor = '#f97316'; activeBg = 'rgba(249, 115, 22, 0.2)'; }
            else if (sev === 'medium') { activeColor = '#eab308'; activeBg = 'rgba(234, 179, 8, 0.2)'; }
            else if (sev === 'low') { activeColor = '#10b981'; activeBg = 'rgba(16, 185, 129, 0.2)'; }

            return (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                style={{
                  flex: 1,
                  padding: '4px 0',
                  fontSize: '11px',
                  fontWeight: isSelected ? 700 : 500,
                  backgroundColor: isSelected ? activeBg : 'rgba(30, 41, 59, 0.4)',
                  color: isSelected ? activeColor : '#94a3b8',
                  border: isSelected ? `1px solid ${activeColor}` : '1px solid rgba(51, 65, 85, 0.4)',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  textTransform: 'capitalize',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '4px',
                  transition: 'all 0.15s ease',
                }}
              >
                {cfg && <span style={{ fontSize: '8px' }}>{cfg.symbol}</span>}
                {sev === 'all' ? 'All' : sev.slice(0, 4)}
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Incident Cards List ── */}
      <div
        role="feed"
        aria-label="Incident Queue"
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: '10px 0',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
        }}
      >
        {loading ? (
          <QueueSkeleton count={5} />
        ) : filteredIncidents.length === 0 ? (
          <div style={{ padding: '36px 16px', textAlign: 'center', color: 'var(--text-muted)' }}>
            <p style={{ fontSize: '13px', fontWeight: 500 }}>No matching incidents</p>
            <p style={{ fontSize: '11.5px', marginTop: '4px', color: '#64748b' }}>Try clearing filters or search term</p>
          </div>
        ) : (
          filteredIncidents.map((inc) => {
            const isSelected = inc.incident_id === selectedIncidentId;
            const sevStyles = getSeverityGlow(inc.severity);
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
                className={`queue-card ${isSelected ? 'selected' : ''}`}
                onClick={() => onSelectIncident(inc.incident_id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onSelectIncident(inc.incident_id);
                  }
                }}
                style={{
                  borderLeft: sevStyles.leftBorder,
                  borderColor: isSelected ? 'var(--accent-cyan)' : undefined,
                  boxShadow: isSelected ? '0 0 12px rgba(0, 240, 255, 0.2)' : undefined,
                }}
              >
                {/* Header Row: Title & Risk Score */}
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '8px' }}>
                  <div
                    style={{
                      fontSize: '12.5px',
                      fontWeight: isSelected ? 700 : 600,
                      color: isSelected ? '#ffffff' : '#f1f5f9',
                      lineHeight: '1.35',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      flex: 1,
                    }}
                    title={title}
                  >
                    {title}
                  </div>

                  {/* Risk Score Pill */}
                  <div
                    className="font-mono"
                    style={{
                      fontSize: '11.5px',
                      fontWeight: 700,
                      padding: '2px 7px',
                      borderRadius: '6px',
                      backgroundColor: sevStyles.scoreBg,
                      color: sevStyles.scoreText,
                      border: `1px solid ${sevStyles.badgeText}40`,
                      flexShrink: 0,
                    }}
                    title={`Risk Score: ${inc.risk_score}/100`}
                  >
                    {inc.risk_score}
                  </div>
                </div>

                {/* Tags Row: Asset & Tactic */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                  {/* Severity Badge */}
                  <span
                    style={{
                      fontSize: '9.5px',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      padding: '1px 6px',
                      borderRadius: '4px',
                      backgroundColor: sevStyles.badgeBg,
                      color: sevStyles.badgeText,
                      letterSpacing: '0.4px',
                    }}
                  >
                    {inc.severity}
                  </span>

                  {/* Asset Chip */}
                  <span
                    style={{
                      fontSize: '10.5px',
                      fontFamily: 'var(--font-mono)',
                      color: '#38bdf8',
                      backgroundColor: 'rgba(56, 189, 248, 0.12)',
                      padding: '1px 6px',
                      borderRadius: '4px',
                      border: '1px solid rgba(56, 189, 248, 0.25)',
                    }}
                  >
                    {asset}
                  </span>

                  {/* Tactic Chip */}
                  {tacticWord && (
                    <span
                      style={{
                        fontSize: '10.5px',
                        textTransform: 'capitalize',
                        color: '#c084fc',
                        backgroundColor: 'rgba(168, 85, 247, 0.12)',
                        padding: '1px 6px',
                        borderRadius: '4px',
                        border: '1px solid rgba(168, 85, 247, 0.25)',
                      }}
                    >
                      {tacticWord}
                    </span>
                  )}
                </div>

                {/* Footer Row: Timestamp & Source */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '10.5px', color: '#64748b', marginTop: '2px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    {inc.is_simulated ? (
                      <span
                        style={{
                          backgroundColor: 'rgba(51, 65, 85, 0.5)',
                          color: '#94a3b8',
                          fontSize: '9px',
                          fontWeight: 600,
                          padding: '1px 5px',
                          borderRadius: '3px',
                        }}
                      >
                        SIMULATED
                      </span>
                    ) : (
                      <span
                        style={{
                          backgroundColor: 'rgba(16, 185, 129, 0.15)',
                          color: '#34d399',
                          fontSize: '9px',
                          fontWeight: 700,
                          padding: '1px 5px',
                          borderRadius: '3px',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '3px',
                        }}
                      >
                        <span style={{ width: '4px', height: '4px', borderRadius: '50%', backgroundColor: '#10b981' }} />
                        LIVE HOST
                      </span>
                    )}

                    {liveIncidentId === inc.incident_id && (
                      <span
                        style={{
                          backgroundColor: 'rgba(249, 115, 22, 0.2)',
                          color: '#fb923c',
                          fontSize: '9px',
                          fontWeight: 700,
                          padding: '1px 5px',
                          borderRadius: '3px',
                        }}
                      >
                        STREAMING
                      </span>
                    )}
                  </div>

                  <span>{timeAgo}</span>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* ── Footer Keyboard Tips ── */}
      <div
        style={{
          padding: '10px 14px',
          borderTop: '1px solid var(--border-subtle)',
          fontSize: '11px',
          color: '#64748b',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          backgroundColor: 'rgba(10, 15, 26, 0.6)',
        }}
      >
        <div style={{ display: 'flex', gap: '8px' }}>
          <span><kbd style={{ fontFamily: 'var(--font-mono)', padding: '1px 5px', background: 'rgba(30, 41, 59, 0.8)', border: '1px solid rgba(51, 65, 85, 0.6)', borderRadius: '3px', color: '#cbd5e1' }}>j</kbd>/<kbd style={{ fontFamily: 'var(--font-mono)', padding: '1px 5px', background: 'rgba(30, 41, 59, 0.8)', border: '1px solid rgba(51, 65, 85, 0.6)', borderRadius: '3px', color: '#cbd5e1' }}>k</kbd> browse</span>
          <span><kbd style={{ fontFamily: 'var(--font-mono)', padding: '1px 5px', background: 'rgba(30, 41, 59, 0.8)', border: '1px solid rgba(51, 65, 85, 0.6)', borderRadius: '3px', color: '#cbd5e1' }}>Enter</kbd> view</span>
        </div>
        {onOpenShortcuts && (
          <button
            onClick={onOpenShortcuts}
            style={{
              background: 'none',
              border: 'none',
              color: '#38bdf8',
              fontSize: '11px',
              cursor: 'pointer',
              fontWeight: 500,
            }}
          >
            Help (?)
          </button>
        )}
      </div>
    </aside>
  );
}
