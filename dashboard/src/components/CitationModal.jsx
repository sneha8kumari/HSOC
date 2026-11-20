import React, { useState, useEffect } from 'react';
import { BookOpen, ShieldAlert, ExternalLink, X, RefreshCw, FileText } from 'lucide-react';

export default function CitationModal({ type, id, incident, onClose }) {
  const [chunkData, setChunkData] = useState(null);
  const [evidenceData, setEvidenceData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id) return;
    setLoading(true);

    if (type === 'chunk') {
      fetch(`/knowledge/chunks/${id}`)
        .then((r) => (r.ok ? r.json() : null))
        .then((data) => setChunkData(data))
        .catch((e) => console.error(e))
        .finally(() => setLoading(false));
    } else if (type === 'evidence') {
      // Find evidence from incident's events or alerts
      if (incident) {
        if (id.startsWith('ALT-')) {
          const alert = incident.alerts?.find((a) => a.alert_id === id);
          setEvidenceData(alert ? { type: 'alert', ...alert } : null);
        } else if (id.startsWith('EVT-')) {
          const event = incident.events?.find((e) => e.event_id === id);
          setEvidenceData(event ? { type: 'event', ...event } : null);
        }
      }
      setLoading(false);
    }
  }, [type, id, incident]);

  if (!id) return null;

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.65)',
        zIndex: 100,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px',
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: '680px',
          maxWidth: '90vw',
          maxHeight: '85vh',
          display: 'flex',
          flexDirection: 'column',
          backgroundColor: 'var(--surface-panel)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-lg)',
          boxShadow: 'var(--shadow-overlay)',
          overflow: 'hidden',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {type === 'chunk' ? (
              <BookOpen size={18} className="text-cyan" />
            ) : (
              <ShieldAlert size={18} className="text-purple" />
            )}
            <span style={{ fontWeight: 700, fontSize: '14px', color: '#fff' }}>
              {type === 'chunk' ? 'KNOWLEDGE PLAYBOOK CHUNK AUDIT' : 'FORENSIC TELEMETRY EVIDENCE'}
            </span>
            <span className="font-mono text-cyan" style={{ fontSize: '12px' }}>
              [{id}]
            </span>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '18px', cursor: 'pointer' }}>
            ✕
          </button>
        </div>

        {/* Modal Body */}
        <div style={{ padding: '20px', overflowY: 'auto', flex: 1, fontSize: '13px', lineHeight: '1.6' }}>
          {loading ? (
            <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
              <RefreshCw size={24} className="pulse-dot" style={{ margin: '0 auto 10px' }} />
              <div>Retrieving verified provenance record...</div>
            </div>
          ) : type === 'chunk' ? (
            chunkData ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div>
                  <div style={{ fontSize: '16px', fontWeight: 700, color: '#fff', marginBottom: '4px' }}>
                    {chunkData.title}
                  </div>
                  <div style={{ display: 'flex', gap: '12px', fontSize: '11.5px', color: 'var(--text-muted)' }}>
                    <span>Source: <strong style={{ color: 'var(--accent-cyan)' }}>{chunkData.source}</strong></span>
                    {chunkData.url && (
                      <a href={chunkData.url} target="_blank" rel="noreferrer" style={{ color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '3px' }}>
                        Authoritative Link <ExternalLink size={11} />
                      </a>
                    )}
                  </div>
                </div>

                <div style={{ background: '#050814', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '16px', color: '#e2e8f0', whiteSpace: 'pre-wrap', fontFamily: 'var(--font-sans)', fontSize: '13px' }}>
                  {chunkData.text}
                </div>

                {chunkData.provenance && (
                  <div style={{ background: 'rgba(0,0,0,0.2)', padding: '10px 14px', borderRadius: '6px', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                    <div><strong>Provenance:</strong> Version: {chunkData.provenance.version || '1.0'} | Domain: {chunkData.domain_tag || 'security'}</div>
                    {chunkData.techniques && <div>Techniques: {chunkData.techniques.join(', ')}</div>}
                  </div>
                )}
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)' }}>Chunk metadata not found in local index.</div>
            )
          ) : (
            evidenceData ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div>
                  <div style={{ fontSize: '15px', fontWeight: 700, color: '#fff', marginBottom: '4px' }}>
                    {evidenceData.type === 'alert' ? `Alert: ${evidenceData.alert_id}` : `Raw Telemetry: ${evidenceData.event_id}`}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Timestamp: {evidenceData.ts}</div>
                </div>

                {evidenceData.raw && (
                  <div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>Raw Log Payload:</div>
                    <div style={{ background: '#050814', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '12px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--accent-cyan)', wordBreak: 'break-all' }}>
                      {evidenceData.raw}
                    </div>
                  </div>
                )}

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', background: 'rgba(0,0,0,0.2)', padding: '12px', borderRadius: '6px', fontSize: '12px' }}>
                  {evidenceData.src_ip && <div><span style={{ color: 'var(--text-muted)' }}>Source IP:</span> <span className="font-mono text-cyan">{evidenceData.src_ip}</span></div>}
                  {evidenceData.dst_host && <div><span style={{ color: 'var(--text-muted)' }}>Destination Host:</span> <span className="font-mono">{evidenceData.dst_host}</span></div>}
                  {evidenceData.user && <div><span style={{ color: 'var(--text-muted)' }}>User:</span> <span className="font-mono">{evidenceData.user}</span></div>}
                  {evidenceData.technique && <div><span style={{ color: 'var(--text-muted)' }}>Technique:</span> <span className="font-mono text-purple">{evidenceData.technique}</span></div>}
                  {evidenceData.outcome && <div><span style={{ color: 'var(--text-muted)' }}>Outcome:</span> <span style={{ textTransform: 'uppercase', fontWeight: 600 }}>{evidenceData.outcome}</span></div>}
                  {evidenceData.action && <div><span style={{ color: 'var(--text-muted)' }}>Action:</span> <span>{evidenceData.action}</span></div>}
                </div>
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)' }}>Evidence item not found in loaded incident cache.</div>
            )
          )}
        </div>
      </div>
    </div>
  );
}
