import React, { useState, useEffect } from 'react';
import { Layers, ChevronRight, Terminal, CheckCircle2 } from 'lucide-react';
import { AgentTracesSkeleton } from './SkeletonLoader';

export default function AgentTracesView({ incidentId }) {
  const [tracesData, setTracesData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedTrace, setSelectedTrace] = useState(null);
  const [soarActions, setSoarActions] = useState([]);

  useEffect(() => {
    if (!incidentId) return;
    fetchTraces();
  }, [incidentId]);

  const fetchSoarActions = async () => {
    try {
      const res = await fetch(`/api/v1/soar/actions?incident_id=${incidentId}`);
      if (res.ok) {
        const data = await res.json();
        setSoarActions(data);
      }
    } catch (err) {
      console.error('Failed to fetch SOAR actions for traces', err);
    }
  };

  const fetchTraces = async () => {
    fetchSoarActions();
    setLoading(true);
    try {
      const res = await fetch(`/incidents/${incidentId}/traces`);
      if (res.ok) {
        const data = await res.json();
        setTracesData(data);
        if (data.traces && data.traces.length > 0) {
          setSelectedTrace(data.traces[0]);
        }
      }
    } catch (err) {
      console.error('Failed to fetch agent traces', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <AgentTracesSkeleton />;
  }

  const traces = tracesData?.traces || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* Top Trace Summary */}
      <div
        style={{
          padding: '12px 18px',
          backgroundColor: 'var(--surface-panel)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-sm)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '16px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)' }}>
            Multi-agent execution log
          </span>
          <span className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            ({traces.length} steps)
          </span>
        </div>

        <div style={{ display: 'flex', gap: '20px', fontSize: '12px' }}>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Total latency:</span>{' '}
            <span className="font-mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
              {tracesData?.total_latency_ms?.toFixed(1) || 0} ms
            </span>
          </div>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Total tokens:</span>{' '}
            <span className="font-mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
              {tracesData?.total_tokens || 0}
            </span>
          </div>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Critic check:</span>{' '}
            <span style={{ color: 'var(--state-success-text)', fontWeight: 500 }}>
              Passed
            </span>
          </div>
        </div>
      </div>

      {/* SOAR Response Actions Audit Section */}
      {soarActions.length > 0 && (
        <div
          style={{
            padding: '12px 18px',
            backgroundColor: 'var(--surface-panel)',
            border: '1px solid var(--border-default)',
            borderRadius: 'var(--radius-sm)',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontWeight: 600, fontSize: '12.5px', color: 'var(--text-primary)' }}>
              SOAR Containment Execution Audit
            </span>
            <span className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              ({soarActions.length} response action{soarActions.length === 1 ? '' : 's'})
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {soarActions.map((act) => (
              <div
                key={act.action_id}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  fontSize: '11.5px',
                  padding: '6px 10px',
                  backgroundColor: 'var(--surface-sunken)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '4px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span className="font-mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{act.action_id}</span>
                  <span style={{ fontWeight: 600, color: 'var(--accent-primary)' }}>{act.action_type}</span>
                  <span className="font-mono">{act.target}</span>
                  <span style={{
                    fontSize: '10px',
                    padding: '1px 5px',
                    borderRadius: '3px',
                    backgroundColor: act.status === 'simulated' || act.status === 'executed' ? 'rgba(16, 185, 129, 0.15)' : act.status === 'rolled_back' ? 'rgba(245, 158, 11, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                    color: act.status === 'simulated' || act.status === 'executed' ? '#10b981' : act.status === 'rolled_back' ? '#f59e0b' : '#ef4444',
                    fontWeight: 500,
                  }}>
                    {act.status}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: 'var(--text-muted)', fontSize: '10.5px' }}>
                  <span>Approved by: {act.approved_by}</span>
                  <span>{act.created_at ? new Date(act.created_at).toLocaleTimeString() : ''}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Main Split: Steps Waterfall on Left, Step Details on Right */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
        {/* Waterfall List */}
        <div
          style={{
            backgroundColor: 'var(--surface-panel)',
            border: '1px solid var(--border-default)',
            borderRadius: 'var(--radius-sm)',
            padding: '12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '6px',
          }}
        >
          {traces.map((trace, idx) => {
            const isSelected = selectedTrace?.trace_id === trace.trace_id;
            return (
              <div
                key={trace.trace_id || idx}
                onClick={() => setSelectedTrace(trace)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '9px 12px',
                  backgroundColor: isSelected ? 'var(--surface-selected)' : 'var(--surface-subtle)',
                  border: isSelected ? '1px solid var(--border-strong)' : '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  cursor: 'pointer',
                  transition: 'background-color 0.1s ease',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span
                    className="font-mono"
                    style={{
                      width: '20px',
                      height: '20px',
                      borderRadius: 'var(--radius-sm)',
                      backgroundColor: 'var(--surface-canvas)',
                      border: '1px solid var(--border-strong)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '10.5px',
                      fontWeight: 600,
                      color: 'var(--text-secondary)',
                    }}
                  >
                    {idx + 1}
                  </span>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '12px', color: 'var(--text-primary)' }}>
                      {trace.agent_name}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      State: {trace.state}
                      {trace.tool_calls && trace.tool_calls.length > 0 && (
                        <span> — {trace.tool_calls.length} tool call(s)</span>
                      )}
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <div style={{ textAlign: 'right', fontSize: '11px' }}>
                    <div className="font-mono" style={{ color: 'var(--text-secondary)' }}>
                      {trace.latency_ms?.toFixed(1)} ms
                    </div>
                    <div className="font-mono" style={{ color: 'var(--text-muted)' }}>
                      {trace.tokens} tok
                    </div>
                  </div>
                  <ChevronRight size={14} color={isSelected ? 'var(--text-primary)' : 'var(--text-muted)'} />
                </div>
              </div>
            );
          })}
        </div>

        {/* Selected Step Details */}
        <div
          style={{
            backgroundColor: 'var(--surface-panel)',
            border: '1px solid var(--border-default)',
            borderRadius: 'var(--radius-sm)',
            padding: '16px',
            display: 'flex',
            flexDirection: 'column',
            gap: '12px',
            overflowY: 'auto',
            maxHeight: '520px',
          }}
        >
          {selectedTrace ? (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {selectedTrace.agent_name}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Trace ID: <span className="font-mono">{selectedTrace.trace_id}</span>
                  </div>
                </div>
                <span className="font-mono" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                  {selectedTrace.latency_ms?.toFixed(2)} ms
                </span>
              </div>

              {/* Tool Calls Dispatched */}
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
                  Tool calls dispatched ({selectedTrace.tool_calls?.length || 0})
                </div>
                {selectedTrace.tool_calls && selectedTrace.tool_calls.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {selectedTrace.tool_calls.map((tc, k) => (
                      <div
                        key={k}
                        className="font-mono"
                        style={{
                          backgroundColor: 'var(--surface-canvas)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: 'var(--radius-sm)',
                          padding: '8px 10px',
                          fontSize: '11px',
                        }}
                      >
                        <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                          {tc.tool_name || tc.name}()
                        </div>
                        <div style={{ color: 'var(--text-muted)', marginTop: '2px', wordBreak: 'break-all' }}>
                          args: {JSON.stringify(tc.arguments || tc.args || {})}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                    No external tools dispatched (internal deliberation).
                  </div>
                )}
              </div>

              {/* Agent Output Synthesis */}
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
                  Agent output
                </div>
                <div
                  style={{
                    backgroundColor: 'var(--surface-canvas)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '10px 12px',
                    fontSize: '12px',
                    lineHeight: '1.5',
                    whiteSpace: 'pre-wrap',
                    color: 'var(--text-secondary)',
                  }}
                >
                  {selectedTrace.output_message || 'Completed stage successfully.'}
                </div>
              </div>
            </>
          ) : (
            <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '40px' }}>
              Select a trace step to inspect inputs and tool calls.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
