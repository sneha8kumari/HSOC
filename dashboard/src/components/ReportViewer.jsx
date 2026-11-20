import React from 'react';
import { FileText, ShieldAlert, BookOpen, ExternalLink, ShieldCheck } from 'lucide-react';
import { getHumanReadableTitle, SEVERITY_CONFIG } from '../utils/incidentHelpers';

export default function ReportViewer({ incident, onOpenChunk, onOpenEvidence }) {
  const report = incident?.report;
  const title = getHumanReadableTitle(incident);
  const sev = SEVERITY_CONFIG[incident?.severity] || SEVERITY_CONFIG.medium;

  if (!report) {
    return (
      <div
        style={{
          padding: '48px 24px',
          textAlign: 'center',
          backgroundColor: 'var(--surface-panel)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-sm)',
          color: 'var(--text-muted)',
        }}
      >
        <FileText size={28} style={{ margin: '0 auto 12px', opacity: 0.6 }} />
        <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
          No investigation report synthesized yet
        </div>
        <div style={{ fontSize: '12px', marginTop: '4px' }}>
          This incident is currently awaiting multi-agent synthesis.
        </div>
      </div>
    );
  }

  // Regex helpers to extract citation links from text
  const renderTextWithCitations = (text) => {
    if (!text) return '';
    const parts = text.split(/(\[KB-[A-Za-z0-9_-]+\]|\[ALT-[A-Za-z0-9_-]+\]|\[EVT-[A-Za-z0-9_-]+\])/g);
    return parts.map((part, i) => {
      if (part.startsWith('[KB-')) {
        const chunkId = part.slice(1, -1);
        return (
          <span
            key={i}
            onClick={() => onOpenChunk && onOpenChunk(chunkId)}
            className="citation-pill"
          >
            <BookOpen size={10} /> {chunkId}
          </span>
        );
      }
      if (part.startsWith('[ALT-') || part.startsWith('[EVT-')) {
        const evId = part.slice(1, -1);
        return (
          <span
            key={i}
            onClick={() => onOpenEvidence && onOpenEvidence(evId)}
            className="evidence-pill"
          >
            <ShieldAlert size={10} /> {evId}
          </span>
        );
      }
      return part;
    });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* Header Metadata Banner */}
      <div
        style={{
          padding: '14px 18px',
          backgroundColor: 'var(--surface-panel)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-sm)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '16px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Investigation report: {title}
            </span>
            <span
              style={{
                backgroundColor: sev.bg,
                color: sev.text,
                border: `1px solid ${sev.color}`,
                borderRadius: 'var(--radius-sm)',
                padding: '1px 6px',
                fontSize: '10.5px',
                fontWeight: 600,
                textTransform: 'uppercase',
              }}
            >
              {sev.symbol} {sev.label}
            </span>
          </div>

          <div
            style={{
              fontSize: '11px',
              color: 'var(--text-muted)',
              marginTop: '4px',
              display: 'flex',
              gap: '12px',
            }}
          >
            <span>Report ID: <strong className="font-mono" style={{ color: 'var(--text-secondary)' }}>{report.report_id}</strong></span>
            <span>Generated: {report.generated_at ? new Date(report.generated_at).toLocaleString() : 'Recent'}</span>
            <span style={{ color: 'var(--state-success-text)', display: 'inline-flex', alignItems: 'center', gap: '3px' }}>
              <ShieldCheck size={12} /> Critic agent verified
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          <a
            href={`/incidents/${incident.incident_id}/copilot/export/jira`}
            target="_blank"
            rel="noreferrer"
            className="btn-secondary"
            style={{ fontSize: '11.5px', padding: '4px 10px' }}
          >
            Export Jira ticket
          </a>
          <a
            href={`/incidents/${incident.incident_id}/copilot/export/servicenow`}
            target="_blank"
            rel="noreferrer"
            className="btn-secondary"
            style={{ fontSize: '11.5px', padding: '4px 10px' }}
          >
            Export ServiceNow SIR
          </a>
        </div>
      </div>

      {/* Executive Summary */}
      <div
        style={{
          padding: '16px 18px',
          backgroundColor: 'var(--surface-panel)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-sm)',
        }}
      >
        <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>
          Executive summary
        </div>
        <div
          style={{
            fontSize: '13px',
            lineHeight: '1.6',
            color: 'var(--text-secondary)',
            maxWidth: '75ch',
          }}
        >
          {renderTextWithCitations(report.summary)}
        </div>
      </div>

      {/* Observed Techniques & Forecasted Next Stages */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
        {/* ATT&CK Techniques */}
        <div
          style={{
            padding: '14px 16px',
            backgroundColor: 'var(--surface-panel)',
            border: '1px solid var(--border-default)',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '10px' }}>
            Observed ATT&CK techniques
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {report.attack_mapping && report.attack_mapping.length > 0 ? (
              report.attack_mapping.map((tech, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '6px 10px',
                    backgroundColor: 'var(--surface-subtle)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '11.5px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="font-mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                      {tech.technique_id}
                    </span>
                    <span style={{ color: 'var(--text-secondary)' }}>
                      {tech.technique_name || tech.name}
                    </span>
                  </div>
                  <span style={{ color: 'var(--text-muted)', textTransform: 'capitalize' }}>
                    {tech.tactic}
                  </span>
                </div>
              ))
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>None listed</div>
            )}
          </div>
        </div>

        {/* Forecasted Next Stages */}
        <div
          style={{
            padding: '14px 16px',
            backgroundColor: 'var(--surface-panel)',
            border: '1px solid var(--border-default)',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '10px' }}>
            Markov forecasted next stages
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {report.predicted_next && report.predicted_next.length > 0 ? (
              report.predicted_next.map((pred, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '6px 10px',
                    backgroundColor: 'var(--surface-subtle)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '11.5px',
                  }}
                >
                  <span style={{ color: 'var(--text-primary)', textTransform: 'capitalize' }}>
                    #{idx + 1} {pred.tactic.replace(/_/g, ' ')}
                  </span>
                  <span className="font-mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                    {(pred.probability * 100).toFixed(1)}%
                  </span>
                </div>
              ))
            ) : (
              <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Terminal or unknown stage</div>
            )}
          </div>
        </div>
      </div>

      {/* Forensic Evidence Citations */}
      <div
        style={{
          padding: '16px 18px',
          backgroundColor: 'var(--surface-panel)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-sm)',
        }}
      >
        <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '10px' }}>
          Forensic evidence citations (Click to inspect raw logs)
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {report.evidence &&
            report.evidence.map((evItem, idx) => (
              <div
                key={idx}
                onClick={() => {
                  const match = evItem.match(/\[(ALT-[A-Za-z0-9_-]+|EVT-[A-Za-z0-9_-]+)\]/);
                  if (match && onOpenEvidence) onOpenEvidence(match[1]);
                }}
                style={{
                  padding: '8px 12px',
                  backgroundColor: 'var(--surface-subtle)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '12px',
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                  maxWidth: '75ch',
                }}
              >
                {renderTextWithCitations(evItem)}
              </div>
            ))}
        </div>
      </div>

      {/* Remediation Checklist */}
      <div
        style={{
          padding: '16px 18px',
          backgroundColor: 'var(--surface-panel)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-sm)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
          <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Playbook containment and remediation checklist
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Actions marked [Approval required] are gated by ActionGuardrail
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {report.remediation &&
            report.remediation.map((rem, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  justifyContent: 'space-between',
                  padding: '10px 12px',
                  backgroundColor: 'var(--surface-subtle)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '12px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', flex: 1, maxWidth: '72ch' }}>
                  <span className="font-mono" style={{ fontWeight: 600, color: 'var(--text-muted)', marginTop: '1px' }}>
                    #{idx + 1}
                  </span>
                  <div>
                    <div style={{ color: 'var(--text-primary)', lineHeight: '1.4' }}>
                      {renderTextWithCitations(rem.step || rem.action)}
                    </div>
                    {rem.source && (
                      <div style={{ marginTop: '4px' }}>
                        <span
                          onClick={() => onOpenChunk && onOpenChunk(rem.source)}
                          className="citation-pill"
                        >
                          <BookOpen size={10} /> Playbook: {rem.source}
                        </span>
                      </div>
                    )}
                  </div>
                </div>

                <div>
                  {rem.needs_approval ? (
                    <span
                      style={{
                        padding: '2px 6px',
                        borderRadius: 'var(--radius-sm)',
                        backgroundColor: 'var(--state-warning-bg)',
                        border: '1px solid var(--state-warning)',
                        color: 'var(--state-warning-text)',
                        fontSize: '10.5px',
                        fontWeight: 600,
                      }}
                    >
                      Approval required
                    </span>
                  ) : (
                    <span
                      style={{
                        padding: '2px 6px',
                        borderRadius: 'var(--radius-sm)',
                        backgroundColor: 'var(--state-success-bg)',
                        border: '1px solid var(--state-success)',
                        color: 'var(--state-success-text)',
                        fontSize: '10.5px',
                      }}
                    >
                      Autonomous
                    </span>
                  )}
                </div>
              </div>
            ))}
        </div>
      </div>
    </div>
  );
}
