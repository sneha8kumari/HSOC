import React, { useState, useEffect } from 'react';
import {
  Copy,
  Check,
  Play,
  Pause,
  RotateCcw,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Shield,
  Activity,
  FileText,
  GitBranch,
  Cpu
} from 'lucide-react';
import { getHumanReadableTitle, getAffectedAsset, getTimeAgo, SEVERITY_CONFIG } from '../utils/incidentHelpers';
import MarkovPanel from './MarkovPanel';
import ReportViewer from './ReportViewer';
import AttackGraph from './AttackGraph';
import AgentTracesView from './AgentTracesView';
import { CaseViewSkeleton } from './SkeletonLoader';

export default function CaseView({
  incident,
  incidentDetail,
  graphData,
  onOpenChunk,
  onOpenEvidence,
  onRefreshIncident,
  loading = false,
  externalActionStatus = null,
  onActionDecision = null,
  liveIncidentId = null,
  lastLiveEvent = null,
}) {
  const [activeTab, setActiveTab] = useState('timeline'); // 'timeline' | 'forecast' | 'report' | 'relationships' | 'traces'
  const [copiedId, setCopiedId] = useState(false);
  const [expandedLogs, setExpandedLogs] = useState({});
  const [showRelationshipsGraph, setShowRelationshipsGraph] = useState(false);

  // Replay state
  const [isReplaying, setIsReplaying] = useState(false);
  const [replaySpeed, setPlaybackSpeed] = useState(5);
  const [currentReplayIdx, setCurrentReplayIdx] = useState(0);
  const [internalActionStatus, setInternalActionStatus] = useState(null);
  const [soarActions, setSoarActions] = useState([]);
  const [currentSoarAction, setCurrentSoarAction] = useState(null);
  const [soarMessage, setSoarMessage] = useState(null);

  const actionStatus = externalActionStatus !== null ? externalActionStatus : internalActionStatus;
  const setActionStatus = (status) => {
    setInternalActionStatus(status);
    if (onActionDecision) onActionDecision(status);
  };

  // Replay animation effect
  useEffect(() => {
    let timer = null;
    const tl = (incidentDetail || incident)?.timeline || [];
    if (isReplaying && tl.length > 0) {
      const intervalMs = Math.max(150, 1500 / replaySpeed);
      timer = setTimeout(() => {
        if (currentReplayIdx < tl.length - 1) {
          const nextIdx = currentReplayIdx + 1;
          setCurrentReplayIdx(nextIdx);
          setExpandedLogs((prev) => ({ ...prev, [nextIdx]: true }));
        } else {
          setIsReplaying(false);
        }
      }, intervalMs);
    }
    return () => {
      if (timer) clearTimeout(timer);
    };
  }, [isReplaying, currentReplayIdx, replaySpeed, incidentDetail, incident]);

  const fetchSoarActions = async () => {
    const incId = (incidentDetail || incident)?.incident_id;
    if (!incId) return;
    try {
      const res = await fetch(`/api/v1/soar/actions?incident_id=${incId}`);
      if (res.ok) {
        const data = await res.json();
        setSoarActions(data);
        const active = data.find((a) => a.status === 'simulated' || a.status === 'executed');
        if (active) {
          setCurrentSoarAction(active);
          setInternalActionStatus('approved');
        }
      }
    } catch (err) {
      console.error('Failed fetching SOAR actions', err);
    }
  };

  useEffect(() => {
    fetchSoarActions();
  }, [incidentDetail, incident]);

  const handleApprove = async () => {
    const incId = (incidentDetail || incident)?.incident_id;
    setActionStatus('approved');
    try {
      const res = await fetch('/api/v1/soar/actions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incident_id: incId,
          step: recommendedAction,
          decision: 'approved',
          approved_by: 'analyst',
        }),
      });
      const data = await res.json();
      if (data.success) {
        setCurrentSoarAction(data);
        setSoarMessage(null);
        fetchSoarActions();
      } else {
        setSoarMessage(data.message || 'Action refused by safety guardrails');
      }
    } catch (err) {
      console.error('Error approving containment step', err);
    }
  };

  const handleReject = async () => {
    const incId = (incidentDetail || incident)?.incident_id;
    setActionStatus('rejected');
    try {
      await fetch('/api/v1/soar/actions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incident_id: incId,
          step: recommendedAction,
          decision: 'rejected',
          approved_by: 'analyst',
        }),
      });
      fetchSoarActions();
    } catch (err) {
      console.error('Error rejecting step', err);
    }
  };

  const handleRollback = async (actionId) => {
    try {
      const res = await fetch(`/api/v1/soar/actions/${actionId}/rollback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Analyst requested rollback' }),
      });
      const data = await res.json();
      if (data.success) {
        if (currentSoarAction?.action_id === actionId) {
          setCurrentSoarAction({ ...currentSoarAction, status: 'rolled_back' });
        }
        fetchSoarActions();
      }
    } catch (err) {
      console.error('Error rolling back action', err);
    }
  };

  const handleToggleReplay = () => {
    const tl = (incidentDetail || incident)?.timeline || [];
    if (!isReplaying) {
      const startIdx = currentReplayIdx >= tl.length - 1 ? 0 : currentReplayIdx;
      setCurrentReplayIdx(startIdx);
      setExpandedLogs({ [startIdx]: true });
      setIsReplaying(true);
    } else {
      setIsReplaying(false);
    }
  };

  const highlightSuspiciousTokens = (text) => {
    if (!text) return '';
    const regex = /(port \d+|403|exploit|cleartext|brute force|\d+ distinct ports|unauthorized|sudo|\b(?:203\.0\.113\.\d+|192\.168\.\d+\.\d+)\b)/gi;
    const parts = text.split(regex);
    return parts.map((part, i) => {
      if (regex.test(part)) {
        return (
          <mark
            key={i}
            style={{
              backgroundColor: 'var(--severity-critical-bg)',
              color: 'var(--severity-critical-text)',
              padding: '1px 4px',
              borderRadius: '2px',
              fontWeight: 600,
            }}
          >
            {part}
          </mark>
        );
      }
      return part;
    });
  };

  if (loading && !incidentDetail) {
    return (
      <main style={{ flex: 1, height: '100%', overflow: 'hidden', backgroundColor: 'var(--surface-canvas)' }}>
        <CaseViewSkeleton />
      </main>
    );
  }

  if (!incident) {
    return (
      <main style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
        <p>Select an incident from the queue to inspect case details.</p>
      </main>
    );
  }

  const detail = incidentDetail || incident;
  const sev = SEVERITY_CONFIG[detail.severity] || SEVERITY_CONFIG.medium;
  const title = getHumanReadableTitle(detail);
  const asset = getAffectedAsset(detail);
  const timeline = detail.timeline || [];
  const report = detail.report;

  const handleCopyId = () => {
    navigator.clipboard?.writeText(detail.incident_id);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
  };

  const toggleLog = (idx) => {
    setExpandedLogs((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  // Plain-language executive summary derivation
  const summaryText = report?.summary ||
    `Incident ${detail.incident_id.slice(0, 8)} detected on target asset ${asset}. Correlated telemetry identified ${timeline.length} stage(s) across tactics [${(detail.tactics || []).join(' -> ')}].`;

  const recommendedAction = report?.remediation?.[0]?.action ||
    `Isolate host ${asset} from internal subnets and inspect authentication logs.`;

  const nodeCount = graphData?.nodes?.length || 0;

  return (
    <main
      style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        overflow: 'hidden',
        backgroundColor: 'var(--surface-canvas)',
      }}
    >
      {/* ── Case Header ── */}
      <div
        style={{
          padding: '14px 20px',
          backgroundColor: 'var(--surface-panel)',
          borderBottom: '1px solid var(--border-default)',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                  backgroundColor: sev.bg,
                  color: sev.text,
                  border: `1px solid ${sev.color}`,
                  borderRadius: 'var(--radius-sm)',
                  padding: '2px 7px',
                  fontSize: '11px',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                }}
              >
                <span>{sev.symbol}</span>
                <span>{sev.label}</span>
              </span>

              {detail.is_simulated ? (
                <span
                  style={{
                    backgroundColor: 'var(--surface-active)',
                    color: 'var(--text-muted)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '2px 7px',
                    fontSize: '10.5px',
                    fontWeight: 600,
                  }}
                  title="This case was generated by the attack scenario engine"
                >
                  SYNTHETIC SCENARIO
                </span>
              ) : (
                <span
                  style={{
                    backgroundColor: 'var(--state-success-bg)',
                    color: 'var(--state-success-text)',
                    border: '1px solid var(--state-success)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '2px 7px',
                    fontSize: '10.5px',
                    fontWeight: 600,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                  }}
                  title="This case was detected from live Windows host or Wazuh telemetry"
                >
                  <span style={{ width: '5px', height: '5px', borderRadius: '50%', backgroundColor: 'var(--state-success)' }} />
                  AUTHENTIC HOST TELEMETRY
                </span>
              )}

              <h1
                style={{
                  fontSize: '16px',
                  fontWeight: 600,
                  color: 'var(--text-primary)',
                  margin: 0,
                  lineHeight: '1.3',
                }}
              >
                {title}
              </h1>
            </div>

            {/* Secondary Metadata Row */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '14px',
                fontSize: '11.5px',
                color: 'var(--text-muted)',
                marginTop: '6px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <span>ID:</span>
                <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>
                  {detail.incident_id}
                </span>
                <button
                  onClick={handleCopyId}
                  title="Copy incident ID"
                  style={{
                    background: 'none',
                    border: 'none',
                    color: copiedId ? 'var(--state-success-text)' : 'var(--text-muted)',
                    cursor: 'pointer',
                    padding: '0 2px',
                    display: 'inline-flex',
                    alignItems: 'center',
                  }}
                >
                  {copiedId ? <Check size={12} /> : <Copy size={12} />}
                </button>
              </div>

              <span>Target: <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontWeight: 500 }}>{asset}</strong></span>
              <span>Risk score: <strong className="font-mono" style={{ color: sev.text }}>{detail.risk_score}</strong></span>
              <span>Status: <strong style={{ color: 'var(--text-primary)', textTransform: 'capitalize' }}>{detail.status || 'Open'}</strong></span>
              <span>Updated: {getTimeAgo(detail.updated_at || detail.created_at)}</span>
            </div>
          </div>
        </div>

        {/* ── Case Navigation Tabs ── */}
        <div
          role="tablist"
          aria-label="Case investigation views"
          style={{ display: 'flex', gap: '2px', borderTop: '1px solid var(--border-subtle)', paddingTop: '10px', marginTop: '4px' }}
        >
          {[
            { id: 'timeline', label: 'Attack timeline', count: timeline.length },
            { id: 'forecast', label: 'Attack forecasting' },
            { id: 'report', label: 'Investigation report' },
            { id: 'relationships', label: 'Relationships', count: nodeCount },
            { id: 'traces', label: 'Execution log' },
          ].map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                role="tab"
                aria-selected={isActive}
                aria-controls={`panel-${tab.id}`}
                id={`tab-${tab.id}`}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  padding: '6px 12px',
                  fontSize: '12px',
                  fontWeight: isActive ? 600 : 400,
                  backgroundColor: isActive ? 'var(--surface-subtle)' : 'transparent',
                  color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                  border: '1px solid',
                  borderColor: isActive ? 'var(--border-strong)' : 'transparent',
                  borderRadius: 'var(--radius-sm)',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  transition: 'background-color 0.1s ease',
                }}
              >
                {tab.label}
                {tab.count !== undefined && (
                  <span
                    className="font-mono"
                    style={{
                      fontSize: '10.5px',
                      color: isActive ? 'var(--text-primary)' : 'var(--text-muted)',
                      backgroundColor: isActive ? 'var(--surface-active)' : 'var(--surface-subtle)',
                      padding: '0 4px',
                      borderRadius: 'var(--radius-sm)',
                    }}
                  >
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Center Content Area ── */}
      <div
        id={`panel-${activeTab}`}
        role="tabpanel"
        aria-labelledby={`tab-${activeTab}`}
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: 'var(--density-case-pad, 16px 20px)',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px',
        }}
      >
        {/* ── Plain-Language Summary Box (Lead with what happened & what to do next) ── */}
        <div
          style={{
            backgroundColor: 'var(--surface-panel)',
            border: '1px solid var(--border-default)',
            borderLeft: `3px solid ${sev.color}`,
            borderRadius: 'var(--radius-sm)',
            padding: 'var(--density-banner-pad, 12px 16px)',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}
        >
          <div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.5px' }}>
              Summary & recommended action
            </div>
            <p style={{ fontSize: '13px', color: 'var(--text-primary)', marginTop: '4px', lineHeight: '1.5' }}>
              {summaryText}
            </p>
          </div>

          <div
            role="status"
            aria-live="polite"
            style={{
              paddingTop: '8px',
              borderTop: '1px solid var(--border-subtle)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '12px',
              fontSize: '12px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
              <span style={{ color: 'var(--text-muted)', fontWeight: 500 }}>Next action:</span>
              <span style={{ color: 'var(--text-primary)' }}>{recommendedAction}</span>
            </div>

            <div style={{ display: 'flex', gap: '6px', flexShrink: 0 }}>
              <button
                onClick={handleApprove}
                aria-label="Approve recommended remediation step (Shortcut: a)"
                className="btn-success"
                style={{ padding: '2px 8px', fontSize: '11px' }}
              >
                {actionStatus === 'approved' ? '? Approved' : 'Approve step'}
              </button>
              <button
                onClick={handleReject}
                aria-label="Reject recommended remediation step (Shortcut: r)"
                className="btn-danger"
                style={{ padding: '2px 8px', fontSize: '11px' }}
              >
                {actionStatus === 'rejected' ? '? Rejected' : 'Reject'}
              </button>
            </div>
          </div>

          {/* SOAR Containment Status Line & Undo */}
          {currentSoarAction && (currentSoarAction.status === 'simulated' || currentSoarAction.status === 'executed') && (
            <div
              style={{
                marginTop: '8px',
                padding: '6px 10px',
                backgroundColor: 'rgba(16, 185, 129, 0.12)',
                border: '1px solid rgba(16, 185, 129, 0.35)',
                borderRadius: '4px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '12px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ color: 'var(--state-success-text, #10b981)', fontWeight: 600 }}>
                  {currentSoarAction.status_line || `Blocked ${currentSoarAction.target} for ${currentSoarAction.ttl_minutes || 30} min, undo`}
                </span>
                <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>(Safe Simulated SOAR)</span>
              </div>
              <button
                onClick={() => handleRollback(currentSoarAction.action_id)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--state-warning, #f59e0b)',
                  textDecoration: 'underline',
                  cursor: 'pointer',
                  fontSize: '11.5px',
                  fontWeight: 600,
                  padding: '1px 4px',
                }}
                aria-label="Undo containment action"
              >
                undo
              </button>
            </div>
          )}

          {currentSoarAction && currentSoarAction.status === 'rolled_back' && (
            <div
              style={{
                marginTop: '8px',
                padding: '5px 10px',
                backgroundColor: 'var(--surface-sunken)',
                border: '1px solid var(--border-default)',
                borderRadius: '4px',
                fontSize: '11.5px',
                color: 'var(--text-muted)',
              }}
            >
              Action on <span className="font-mono">{currentSoarAction.target}</span> rolled back successfully.
            </div>
          )}

          {soarMessage && (
            <div
              style={{
                marginTop: '8px',
                padding: '5px 10px',
                backgroundColor: 'rgba(239, 68, 68, 0.12)',
                border: '1px solid rgba(239, 68, 68, 0.35)',
                borderRadius: '4px',
                fontSize: '11.5px',
                color: 'var(--state-danger-text, #ef4444)',
              }}
            >
              {soarMessage}
            </div>
          )}

          {/* Response Actions Audit List */}
          {soarActions.length > 0 && (
            <div
              style={{
                marginTop: '8px',
                padding: '8px 10px',
                backgroundColor: 'var(--surface-sunken)',
                border: '1px solid var(--border-default)',
                borderRadius: '4px',
                display: 'flex',
                flexDirection: 'column',
                gap: '4px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '10.5px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                <span>Response actions ({soarActions.length})</span>
                <span style={{ fontSize: '9.5px', color: 'var(--text-muted)' }}>SOAR Audit Log</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                {soarActions.map((act) => (
                  <div key={act.action_id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px', padding: '2px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span className="font-mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{act.action_type}</span>
                      <span style={{ color: 'var(--text-secondary)' }}>{act.target}</span>
                      <span style={{
                        fontSize: '9.5px',
                        padding: '1px 4px',
                        borderRadius: '3px',
                        backgroundColor: act.status === 'simulated' || act.status === 'executed' ? 'rgba(16, 185, 129, 0.15)' : act.status === 'rolled_back' ? 'rgba(245, 158, 11, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                        color: act.status === 'simulated' || act.status === 'executed' ? '#10b981' : act.status === 'rolled_back' ? '#f59e0b' : '#ef4444',
                        fontWeight: 500,
                      }}>
                        {act.status}
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>by {act.approved_by}</span>
                      {(act.status === 'simulated' || act.status === 'executed') && (
                        <button
                          onClick={() => handleRollback(act.action_id)}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: 'var(--state-warning, #f59e0b)',
                            cursor: 'pointer',
                            textDecoration: 'underline',
                            fontSize: '10.5px',
                            fontWeight: 600,
                          }}
                        >
                          Undo
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

                {/* ── Tab: Attack Timeline (Primary Visual) ── */}
        {activeTab === 'timeline' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {/* Timeline Header & Replay Inline Toolbar */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                paddingBottom: '8px',
                borderBottom: '1px solid var(--border-default)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontWeight: 600, fontSize: '13px' }}>Attack progression</span>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  ({timeline.length} sequential event{timeline.length === 1 ? '' : 's'})
                </span>
                {liveIncidentId === (incidentDetail?.incident_id || incident?.incident_id) && (
                  <span
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                      backgroundColor: 'var(--state-success-bg)',
                      color: 'var(--state-success-text)',
                      border: '1px solid var(--state-success)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '1px 6px',
                      fontSize: '10.5px',
                      fontWeight: 500,
                    }}
                  >
                    <span style={{ width: '5px', height: '5px', borderRadius: '50%', backgroundColor: 'var(--state-success)' }} />
                    Live stream active
                  </span>
                )}
              </div>

              {/* Inline Attack Replay Controls */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <button
                  onClick={handleToggleReplay}
                  className="btn-primary"
                  style={{ fontSize: '11.5px', padding: '3px 10px' }}
                >
                  {isReplaying ? <Pause size={12} /> : <Play size={12} />}
                  <span>{isReplaying ? 'Pause' : 'Replay this attack'}</span>
                </button>

                <div
                  style={{
                    display: 'inline-flex',
                    border: '1px solid var(--border-default)',
                    borderRadius: 'var(--radius-sm)',
                    overflow: 'hidden',
                  }}
                >
                  {[1, 5, 10].map((spd) => (
                    <button
                      key={spd}
                      onClick={() => setPlaybackSpeed(spd)}
                      style={{
                        padding: '2px 7px',
                        fontSize: '10.5px',
                        border: 'none',
                        borderRight: spd !== 10 ? '1px solid var(--border-subtle)' : 'none',
                        backgroundColor: replaySpeed === spd ? 'var(--surface-active)' : 'var(--surface-subtle)',
                        color: replaySpeed === spd ? 'var(--text-primary)' : 'var(--text-muted)',
                        cursor: 'pointer',
                        fontFamily: 'var(--font-mono)',
                      }}
                    >
                      {spd}x
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Vertical Sequential Timeline */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0', position: 'relative' }}>
              {timeline.length === 0 ? (
                <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No progression stages recorded for this incident.
                </div>
              ) : (
                timeline.map((step, idx) => {
                  const isLast = idx === timeline.length - 1;
                  const isExpanded = expandedLogs[idx];
                  const stageName = (step.tactic || 'activity').replace(/_/g, ' ');
                  const isReplayActive = isReplaying && currentReplayIdx === idx;

                  return (
                    <div
                      key={step.alert_id || idx}
                      style={{
                        display: 'flex',
                        gap: '14px',
                        paddingBottom: isLast ? '8px' : '16px',
                        position: 'relative',
                      }}
                    >
                      {/* Vertical line connecting stages */}
                      {!isLast && (
                        <div
                          style={{
                            position: 'absolute',
                            left: '11px',
                            top: '24px',
                            bottom: '0',
                            width: '2px',
                            backgroundColor: 'var(--border-default)',
                          }}
                        />
                      )}

                      {/* Sequence Number Bullet */}
                      <div
                        className="font-mono"
                        style={{
                          width: '24px',
                          height: '24px',
                          borderRadius: '50%',
                          backgroundColor: isReplayActive ? 'var(--border-focus)' : 'var(--surface-subtle)',
                          border: isReplayActive ? '2px solid var(--text-primary)' : '2px solid var(--border-strong)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: '11px',
                          fontWeight: 600,
                          color: isReplayActive ? '#ffffff' : 'var(--text-primary)',
                          zIndex: 1,
                          flexShrink: 0,
                          transition: 'background-color 0.2s ease',
                        }}
                      >
                        {idx + 1}
                      </div>

                      {/* Stage Body */}
                      <div
                        style={{
                          flex: 1,
                          backgroundColor: isReplayActive ? 'var(--surface-hover)' : 'var(--surface-panel)',
                          border: isReplayActive ? '1px solid var(--border-focus)' : '1px solid var(--border-default)',
                          borderRadius: 'var(--radius-sm)',
                          padding: '10px 14px',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '6px',
                          transition: 'border-color 0.2s ease, background-color 0.2s ease',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ fontWeight: 600, fontSize: '13px', textTransform: 'capitalize' }}>
                              {stageName}
                            </span>
                            <span
                              className="font-mono"
                              style={{
                                fontSize: '11px',
                                color: 'var(--text-muted)',
                                backgroundColor: 'var(--surface-subtle)',
                                padding: '1px 5px',
                                borderRadius: 'var(--radius-sm)',
                              }}
                            >
                              {step.technique}
                            </span>

                            {/* Out-of-order stage marker */}
                            {step.out_of_order && (
                              <span
                                title="This step happened before an earlier stage was seen"
                                style={{
                                  fontSize: '11px',
                                  color: 'var(--state-warning-text)',
                                  backgroundColor: 'var(--state-warning-bg)',
                                  border: '1px solid var(--state-warning)',
                                  padding: '1px 6px',
                                  borderRadius: 'var(--radius-sm)',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '4px',
                                  cursor: 'help',
                                }}
                              >
                                <AlertTriangle size={11} /> Out of order
                              </span>
                            )}

                            {isReplayActive && (
                              <span style={{ fontSize: '11px', color: 'var(--border-focus)', fontWeight: 600 }}>
                                Active replay step
                              </span>
                            )}
                          </div>

                          <span className="font-mono" style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                            {step.ts ? new Date(step.ts).toLocaleTimeString() : 'Recent'}
                          </span>
                        </div>

                        {/* Description */}
                        <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                          {step.description || 'Observed telemetry event matching rule signature.'}
                        </div>

                        {/* Inline Expandable Log Snippet Button */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginTop: '2px' }}>
                          <button
                            onClick={() => toggleLog(idx)}
                            style={{
                              background: 'none',
                              border: 'none',
                              color: 'var(--text-muted)',
                              fontSize: '11.5px',
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px',
                              padding: 0,
                            }}
                          >
                            {isExpanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                            <span>{isExpanded ? 'Hide telemetry log' : 'Inspect telemetry log'}</span>
                          </button>

                          {step.alert_id && (
                            <span
                              onClick={() => onOpenEvidence && onOpenEvidence(`ALT-${step.alert_id}`)}
                              className="evidence-pill"
                              style={{ cursor: 'pointer' }}
                            >
                              Alert {step.alert_id.slice(0, 8)}
                            </span>
                          )}
                        </div>

                        {/* Expandable Monospace Log Snippet with highlighted suspicious part */}
                        {isExpanded && (
                          <div
                            className="font-mono"
                            style={{
                              marginTop: '6px',
                              backgroundColor: 'var(--surface-canvas)',
                              border: '1px dashed var(--border-strong)',
                              borderRadius: 'var(--radius-sm)',
                              padding: '10px 12px',
                              fontSize: '11.5px',
                              lineHeight: '1.5',
                              overflowX: 'auto',
                              color: 'var(--text-secondary)',
                            }}
                          >
                            <div style={{ color: 'var(--text-muted)', marginBottom: '4px' }}>
                              # Raw telemetry for Alert {step.alert_id}:
                            </div>
                            <div>
                              timestamp: <span style={{ color: 'var(--text-primary)' }}>{step.ts || new Date().toISOString()}</span>
                            </div>
                            <div>
                              technique: <span style={{ color: 'var(--text-primary)' }}>{step.technique}</span> (tactic: {step.tactic})
                            </div>
                            <div>
                              target_asset: <span style={{ color: 'var(--text-primary)' }}>{asset}</span>
                            </div>
                            <div style={{ marginTop: '4px', color: 'var(--text-primary)' }}>
                              payload: {highlightSuspiciousTokens(step.description || 'Raw telemetry payload')}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        )}

        {/* ── Tab: Markov Attack Forecasting ── */}
        {activeTab === 'forecast' && (
          <MarkovPanel selectedIncident={detail} />
        )}

        {/* ── Tab: Investigation Report ── */}
        {activeTab === 'report' && (
          <ReportViewer
            incident={detail}
            onOpenChunk={onOpenChunk}
            onOpenEvidence={onOpenEvidence}
          />
        )}

        {/* ── Tab: Relationships (Graph or Clean List) ── */}
        {activeTab === 'relationships' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <span style={{ fontWeight: 600, fontSize: '13px' }}>Attack relationship topology</span>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)', marginLeft: '8px' }}>
                  ({nodeCount} entities and alerts)
                </span>
              </div>

              {/* Toggle between structured list and graph view */}
              <div style={{ display: 'flex', gap: '6px' }}>
                <button
                  onClick={() => setShowRelationshipsGraph(false)}
                  style={{
                    padding: '3px 8px',
                    fontSize: '11.5px',
                    backgroundColor: !showRelationshipsGraph ? 'var(--surface-active)' : 'transparent',
                    color: !showRelationshipsGraph ? 'var(--text-primary)' : 'var(--text-secondary)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 'var(--radius-sm)',
                    cursor: 'pointer',
                  }}
                >
                  Structured list
                </button>
                <button
                  onClick={() => setShowRelationshipsGraph(true)}
                  style={{
                    padding: '3px 8px',
                    fontSize: '11.5px',
                    backgroundColor: showRelationshipsGraph ? 'var(--surface-active)' : 'transparent',
                    color: showRelationshipsGraph ? 'var(--text-primary)' : 'var(--text-secondary)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 'var(--radius-sm)',
                    cursor: 'pointer',
                  }}
                >
                  Interactive graph
                </button>
              </div>
            </div>

            {/* If < 6 nodes and not explicitly graph, show clean readable list */}
            {(!showRelationshipsGraph && nodeCount < 6) ? (
              <div
                style={{
                  backgroundColor: 'var(--surface-panel)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '16px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '12px',
                }}
              >
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  This incident has {nodeCount} correlated entities. Displayed as a direct relationship sequence:
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {(graphData?.nodes || []).map((node, i) => (
                    <div
                      key={node.id}
                      style={{
                        padding: '8px 12px',
                        backgroundColor: 'var(--surface-subtle)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-sm)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <span className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          #{i + 1}
                        </span>
                        <span style={{ fontWeight: 500, fontSize: '12.5px' }}>{node.label || node.id}</span>
                        <span
                          style={{
                            fontSize: '11px',
                            color: 'var(--text-muted)',
                            textTransform: 'capitalize',
                          }}
                        >
                          ({node.type.replace('entity_', '')})
                        </span>
                      </div>

                      {node.technique && (
                        <span className="font-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                          {node.technique}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div style={{ height: '460px' }}>
                <AttackGraph
                  incidentId={detail.incident_id}
                  graphData={graphData}
                  onSelectNode={(node) => console.log('Selected node', node)}
                />
              </div>
            )}
          </div>
        )}

        {/* ── Tab: Execution Log / Traces ── */}
        {activeTab === 'traces' && (
          <AgentTracesView incidentId={detail.incident_id} />
        )}
      </div>
    </main>
  );
}
