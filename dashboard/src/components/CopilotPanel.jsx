import React, { useState, useRef, useEffect } from 'react';
import {
  Bot,
  Send,
  Sliders,
  CheckCircle2,
  XCircle,
  Edit3,
  RefreshCw,
  AlertCircle,
  Square,
  RotateCw,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  BookOpen,
  Activity,
  Cpu,
  Sparkles,
  Shield
} from 'lucide-react';
import { getAffectedAsset } from '../utils/incidentHelpers';

export default function CopilotPanel({ incident, onRefreshIncident, onOpenChunk, onOpenEvidence }) {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      text: `Hello. I am your H-SOC incident assistant. I have synthesized telemetry and playbook evidence for this case. Ask about attack progression, severity rationale, or run what-if simulations.`,
      citations: [],
      timestamp: new Date().toLocaleTimeString(),
    },
  ]);
  const [input, setInput] = useState('');
  const [isStreaming, setIsStreaming] = useState(false);
  const [streamProgress, setStreamProgress] = useState('');
  const [lastQuery, setLastQuery] = useState('');
  const [activeTab, setActiveTab] = useState('chat'); // 'chat' | 'whatif' | 'feedback'
  const [providerInfo, setProviderInfo] = useState({ provider: 'ollama', status: 'checking', model: 'llama3:8b' });

  // Fetch AI provider status on mount
  useEffect(() => {
    fetch('/api/v1/telemetry/health')
      .then((r) => r.json())
      .then((data) => {
        if (data.components?.ai_copilot) {
          setProviderInfo(data.components.ai_copilot);
        }
      })
      .catch(() => {
        setProviderInfo({ provider: 'offline_heuristic', status: 'fallback', model: 'deterministic_rag' });
      });
  }, []);

  // Reader ref for stop generation
  const activeReaderRef = useRef(null);

  // What-if state
  const [forcedState, setForcedState] = useState('privilege_escalation');
  const [assetCrit, setAssetCrit] = useState(5);
  const [whatIfResult, setWhatIfResult] = useState(null);
  const [simulating, setSimulating] = useState(false);

  // Feedback state
  const [feedbackStatus, setFeedbackStatus] = useState(null);
  const [actionFeedbackState, setActionFeedbackState] = useState({});

  const asset = getAffectedAsset(incident);

  // Dynamic suggested questions from current case
  const suggestedQuestions = [
    `Why was this assigned a ${incident?.severity?.toUpperCase() || 'HIGH'} severity score?`,
    `What is the predicted next progression stage for ${asset}?`,
    `What if the attacker obtains domain admin or root access on ${asset}?`,
    `Show raw evidence and telemetry citations for stage 1`,
  ];

  const handleStop = async () => {
    if (activeReaderRef.current) {
      try {
        await activeReaderRef.current.cancel();
      } catch (e) {
        // ignore
      }
      activeReaderRef.current = null;
    }
    setIsStreaming(false);
    setStreamProgress('');
  };

  const handleSend = async (queryText) => {
    const q = queryText || input;
    if (!q.trim() || !incident) return;

    setInput('');
    setLastQuery(q);
    const newMessages = [
      ...messages,
      { role: 'user', text: q, citations: [], timestamp: new Date().toLocaleTimeString() },
    ];
    setMessages(newMessages);
    setIsStreaming(true);
    setStreamProgress('Connecting to Copilot RAG pipeline...');

    try {
      const res = await fetch(`/incidents/${incident.incident_id}/copilot/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q, question: q, stream: true }),
      });

      if (!res.ok) {
        throw new Error(`Copilot response status ${res.status}`);
      }

      const reader = res.body.getReader();
      activeReaderRef.current = reader;
      const decoder = new TextDecoder('utf-8');
      let botResponse = '';
      let citations = [];
      let sseBuffer = '';

      // Append assistant placeholder
      setMessages([
        ...newMessages,
        {
          role: 'assistant',
          text: '',
          citations: [],
          timestamp: new Date().toLocaleTimeString(),
          canFeedback: true,
        },
      ]);

      const processSSEBlock = (block) => {
        const lines = block.split(/\r?\n/);
        let dataPayload = '';
        for (const line of lines) {
          if (line.startsWith(':')) {
            // Heartbeat / comment - ignore
            continue;
          }
          if (line.startsWith('data:')) {
            const content = line.slice(5).trim();
            if (content === '[DONE]') {
              return true;
            }
            dataPayload += content;
          }
        }

        if (dataPayload) {
          try {
            const parsed = JSON.parse(dataPayload);
            if (parsed.type === 'progress') {
              setStreamProgress(parsed.detail || `Stage: ${parsed.stage}`);
            } else if (parsed.token) {
              botResponse += parsed.token;
              setMessages([
                ...newMessages,
                {
                  role: 'assistant',
                  text: botResponse,
                  citations,
                  timestamp: new Date().toLocaleTimeString(),
                  canFeedback: true,
                },
              ]);
            }
            if (parsed.citations && parsed.citations.length > 0) {
              citations = [...new Set([...citations, ...parsed.citations])];
              setMessages([
                ...newMessages,
                {
                  role: 'assistant',
                  text: botResponse,
                  citations,
                  timestamp: new Date().toLocaleTimeString(),
                  canFeedback: true,
                },
              ]);
            }
          } catch (e) {
            // Malformed JSON segment, safely ignore
          }
        }
        return false;
      };

      while (true) {
        const { value, done } = await reader.read();
        if (done) {
          if (sseBuffer.trim()) {
            processSSEBlock(sseBuffer.trim());
          }
          break;
        }

        sseBuffer += decoder.decode(value, { stream: true });

        // SSE events are separated by double newline \n\n or \r\n\r\n
        let boundaryIndex;
        while ((boundaryIndex = sseBuffer.search(/\r?\n\r?\n/)) !== -1) {
          const match = sseBuffer.match(/\r?\n\r?\n/);
          const sepLen = match ? match[0].length : 2;
          const block = sseBuffer.slice(0, boundaryIndex);
          sseBuffer = sseBuffer.slice(boundaryIndex + sepLen);

          if (block.trim()) {
            const isDone = processSSEBlock(block);
            if (isDone) break;
          }
        }
      }
    } catch (err) {
      console.error('Copilot request failed:', err);
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          text: `The assistant could not complete this request. (Offline deterministic RAG fallback available).`,
          citations: [],
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      activeReaderRef.current = null;
      setIsStreaming(false);
      setStreamProgress('');
    }
  };

  const handleActionDecision = async (idx, decision) => {
    setActionFeedbackState((prev) => ({ ...prev, [idx]: decision }));
    await submitFeedback(decision);
  };

  const runWhatIf = async () => {
    if (!incident) return;
    setSimulating(true);
    setWhatIfResult(null);

    try {
      const res = await fetch(`/incidents/${incident.incident_id}/copilot/what-if`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          forced_state: forcedState,
          hypothetical_asset_criticality: assetCrit,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setWhatIfResult(data);
      }
    } catch (e) {
      console.error('What-if simulation error:', e);
    } finally {
      setSimulating(false);
    }
  };

  const submitFeedback = async (decision, correctedDst = null) => {
    if (!incident || !incident.tactics || incident.tactics.length < 1) return;
    const src = incident.tactics[0] || 'reconnaissance';
    const dst = incident.tactics[1] || 'initial_access';

    setFeedbackStatus('Submitting analyst decision...');
    try {
      const res = await fetch('/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incident_id: incident.incident_id,
          analyst_id: 'analyst_current',
          decision,
          src_tactic: src,
          dst_tactic: dst,
          corrected_dst_tactic: correctedDst,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setFeedbackStatus(`Updated Markov Dirichlet prior model to v${data.current_version}. Delta: ${data.bayesian_update.delta}`);
        if (onRefreshIncident) onRefreshIncident();
      }
    } catch (e) {
      setFeedbackStatus(`Failed to update feedback: ${e.message}`);
    }
  };

  // Render text with clickable inline citations
  const renderTextWithCitations = (text) => {
    if (!text) return '';
    const parts = text.split(/(\[KB-[A-Za-z0-9_-]+\]|\[ALT-[A-Za-z0-9_-]+\]|\[EVT-[A-Za-z0-9_-]+\]|\[[0-9a-fA-F-]{8,}\])/g);
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
      if (part.startsWith('[ALT-') || part.startsWith('[EVT-') || (/^\[[0-9a-fA-F-]{8,}\]$/).test(part)) {
        const evId = part.slice(1, -1);
        return (
          <span
            key={i}
            onClick={() => onOpenEvidence && onOpenEvidence(evId)}
            className="evidence-pill"
          >
            <ShieldAlert size={10} /> {evId.slice(0, 12)}
          </span>
        );
      }
      return part;
    });
  };

  return (
    <div
      style={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        backgroundColor: 'var(--surface-panel)',
        overflow: 'hidden',
      }}
    >
      {/* ── Tabs (Calm neutral buttons) ── */}
      <div
        role="tablist"
        aria-label="Assistant views"
        style={{ display: 'flex', borderBottom: '1px solid var(--border-default)', backgroundColor: 'var(--surface-panel)' }}
      >
        {[
          { id: 'chat', label: 'Case briefing', icon: <Bot size={13} /> },
          { id: 'whatif', label: 'What-if simulation', icon: <Sliders size={13} /> },
          { id: 'feedback', label: 'Analyst feedback', icon: <Edit3 size={13} /> },
        ].map((t) => {
          const isActive = activeTab === t.id;
          return (
            <button
              key={t.id}
              role="tab"
              aria-selected={isActive}
              aria-controls={`assistant-panel-${t.id}`}
              onClick={() => setActiveTab(t.id)}
              style={{
                flex: 1,
                padding: '10px 6px',
                backgroundColor: isActive ? 'var(--surface-subtle)' : 'transparent',
                border: 'none',
                borderBottom: isActive ? '2px solid var(--border-focus)' : '2px solid transparent',
                color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                fontWeight: isActive ? 600 : 400,
                fontSize: '11.5px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '6px',
                cursor: 'pointer',
              }}
            >
              {t.icon}
              <span>{t.label}</span>
            </button>
          );
        })}
      </div>

      {/* ── Tab: Chat Briefing ── */}
      {activeTab === 'chat' && (
        <div
          id="assistant-panel-chat"
          role="tabpanel"
          aria-label="Case briefing"
          style={{ flex: 1, display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}
        >
          {/* Provider & Safety Status Bar */}
          <div
            style={{
              padding: '6px 12px',
              backgroundColor: 'var(--surface-subtle)',
              borderBottom: '1px solid var(--border-subtle)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              fontSize: '11px',
              color: 'var(--text-secondary)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span
                style={{
                  width: '6px',
                  height: '6px',
                  borderRadius: '50%',
                  backgroundColor: providerInfo.status === 'ok' ? 'var(--state-success)' : 'var(--state-warning)',
                }}
              />
              <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>
                {providerInfo.provider === 'ollama' ? 'Ollama Local' : providerInfo.provider === 'mistral' ? 'Mistral Cloud' : 'Hybrid RAG'}
              </span>
              <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '10px' }}>({providerInfo.model || 'grounded'})</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '10px', color: 'var(--text-muted)' }}>
              <ShieldCheck size={11} style={{ color: 'var(--state-success)' }} />
              <span>Prompt-injection guardrails</span>
            </div>
          </div>

          {/* Messages Log (Plain paragraphs, no heavy bubbles) */}
          <div
            role="log"
            aria-live="polite"
            aria-atomic="false"
            style={{ flex: 1, overflowY: 'auto', padding: '14px', display: 'flex', flexDirection: 'column', gap: '14px' }}
          >
            {messages.map((msg, idx) => {
              const isUser = msg.role === 'user';
              const feedbackState = actionFeedbackState[idx];

              return (
                <div
                  key={idx}
                  style={{
                    backgroundColor: isUser ? 'var(--surface-active)' : 'var(--surface-subtle)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '10px 12px',
                    fontSize: '12.5px',
                    lineHeight: '1.5',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', fontSize: '10.5px', color: 'var(--text-muted)' }}>
                    <span style={{ fontWeight: 600, color: isUser ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                      {isUser ? 'Analyst inquiry' : 'Assistant synthesis'}
                    </span>
                    <span>{msg.timestamp}</span>
                  </div>

                  <div style={{ color: 'var(--text-primary)', whiteSpace: 'pre-wrap' }}>
                    {renderTextWithCitations(msg.text)}
                  </div>

                  {/* Inline Citations Links */}
                  {msg.citations && msg.citations.length > 0 && (
                    <div style={{ marginTop: '8px', paddingTop: '6px', borderTop: '1px solid var(--border-subtle)', display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                      <span style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>Grounded evidence:</span>
                      {msg.citations.map((c, cIdx) => (
                        <span
                          key={cIdx}
                          onClick={() => {
                            if (c.startsWith('KB-') && onOpenChunk) onOpenChunk(c);
                            if ((c.startsWith('ALT-') || c.startsWith('EVT-') || c.length > 8) && onOpenEvidence) {
                              onOpenEvidence(c);
                            }
                          }}
                          className={c.startsWith('KB-') ? 'citation-pill' : 'evidence-pill'}
                        >
                          {c.slice(0, 16)}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Action Controls next to recommendation */}
                  {!isUser && msg.canFeedback && (
                    <div
                      style={{
                        marginTop: '8px',
                        paddingTop: '6px',
                        borderTop: '1px solid var(--border-subtle)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                      }}
                    >
                      <span style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>Recommended action:</span>
                      <div style={{ display: 'flex', gap: '6px' }}>
                        <button
                          onClick={() => handleActionDecision(idx, 'approved')}
                          className="btn-success"
                          style={{ padding: '2px 8px', fontSize: '10.5px' }}
                        >
                          {feedbackState === 'approved' ? '✓ Approved' : 'Approve step'}
                        </button>
                        <button
                          onClick={() => handleActionDecision(idx, 'edit')}
                          className="btn-secondary"
                          style={{ padding: '2px 8px', fontSize: '10.5px' }}
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleActionDecision(idx, 'rejected')}
                          className="btn-danger"
                          style={{ padding: '2px 8px', fontSize: '10.5px' }}
                        >
                          {feedbackState === 'rejected' ? '✗ Rejected' : 'Reject'}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}

            {/* Named Progress Status Banner while Streaming */}
            {isStreaming && (
              <div
                role="status"
                aria-live="polite"
                style={{
                  padding: '8px 12px',
                  backgroundColor: 'var(--surface-subtle)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 'var(--radius-sm)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  fontSize: '11.5px',
                  color: 'var(--text-secondary)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Activity size={12} style={{ color: 'var(--border-focus)' }} />
                  <span>{streamProgress || 'Generating response...'}</span>
                </div>
                <button
                  onClick={handleStop}
                  aria-label="Stop generation"
                  className="btn-secondary"
                  style={{ padding: '2px 6px', fontSize: '10.5px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                >
                  <Square size={10} /> Stop
                </button>
              </div>
            )}
          </div>

          {/* Suggested Questions List (Not clipped pills, plain clean vertical list) */}
          <div style={{ padding: '8px 12px', borderTop: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>Case-specific questions:</span>
              {lastQuery && !isStreaming && (
                <button
                  onClick={() => handleSend(lastQuery)}
                  style={{ background: 'none', border: 'none', color: 'var(--border-focus)', fontSize: '10.5px', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '3px' }}
                >
                  <RotateCw size={10} /> Retry last query
                </button>
              )}
            </div>

            {suggestedQuestions.map((q, qIdx) => (
              <button
                key={qIdx}
                onClick={() => handleSend(q)}
                disabled={isStreaming}
                style={{
                  textAlign: 'left',
                  padding: '4px 8px',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'transparent',
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-secondary)',
                  fontSize: '11px',
                  cursor: isStreaming ? 'not-allowed' : 'pointer',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
                onMouseEnter={(e) => {
                  if (!isStreaming) {
                    e.currentTarget.style.backgroundColor = 'var(--surface-hover)';
                    e.currentTarget.style.color = 'var(--text-primary)';
                  }
                }}
                onMouseLeave={(e) => {
                  if (!isStreaming) {
                    e.currentTarget.style.backgroundColor = 'transparent';
                    e.currentTarget.style.color = 'var(--text-secondary)';
                  }
                }}
              >
                › {q}
              </button>
            ))}
          </div>

          {/* Input Box */}
          <div style={{ padding: '10px 12px', borderTop: '1px solid var(--border-default)', display: 'flex', gap: '6px' }}>
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSend()}
              placeholder="Ask a question about this incident..."
              disabled={isStreaming}
              className="input-text"
              style={{ flex: 1, fontSize: '12px' }}
            />
            {isStreaming ? (
              <button
                onClick={handleStop}
                className="btn-danger"
                style={{ padding: '6px 10px', fontSize: '11.5px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
              >
                <Square size={12} /> Stop
              </button>
            ) : (
              <button
                onClick={() => handleSend()}
                disabled={!input.trim()}
                className="btn-primary"
                style={{ padding: '6px 10px' }}
              >
                <Send size={13} />
              </button>
            )}
          </div>
        </div>
      )}

      {/* ── Tab: What-If Simulator with Before/After Forecast Comparison ── */}
      {activeTab === 'whatif' && (
        <div style={{ padding: '14px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div>
            <div style={{ fontWeight: 600, fontSize: '12.5px', color: 'var(--text-primary)' }}>
              What-if counterfactual simulation
            </div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '2px' }}>
              Evaluate hypothesis boundaries: test how attacker escalation alters Markov trajectory and containment.
            </div>
          </div>

          <div>
            <label style={{ fontSize: '11px', color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
              Hypothetical escalation:
            </label>
            <select
              value={forcedState}
              onChange={(e) => setForcedState(e.target.value)}
              style={{
                width: '100%',
                padding: '6px 8px',
                backgroundColor: 'var(--surface-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-primary)',
                fontSize: '12px',
                outline: 'none',
              }}
            >
              <option value="privilege_escalation">Assume the attacker gets [root access / sudo exploit]</option>
              <option value="lateral_movement">Assume the attacker gets [lateral movement to internal subnet]</option>
              <option value="credential_access">Assume the attacker gets [domain admin credentials]</option>
              <option value="exfiltration">Assume the attacker reaches [data exfiltration stage]</option>
            </select>
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
              <span>Asset criticality:</span>
              <span className="font-mono">{assetCrit} / 5</span>
            </div>
            <input
              type="range"
              min="1"
              max="5"
              value={assetCrit}
              onChange={(e) => setAssetCrit(parseInt(e.target.value, 10))}
              style={{ width: '100%', accentColor: 'var(--border-focus)' }}
            />
          </div>

          <button onClick={runWhatIf} disabled={simulating} className="btn-primary" style={{ justifyContent: 'center' }}>
            {simulating ? 'Computing counterfactual projection...' : 'Run what-if projection'}
          </button>

          {/* Before / After Comparison Cards */}
          {whatIfResult && (
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '10px',
                backgroundColor: 'var(--surface-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 'var(--radius-sm)',
                padding: '12px',
              }}
            >
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                Before / After Forecast Comparison
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                {/* Before Card */}
                <div style={{ padding: '8px', backgroundColor: 'var(--surface-panel)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)' }}>
                  <div style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>Baseline Case</div>
                  <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                    {incident?.risk_score || 80}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Risk score</div>
                </div>

                {/* After Card */}
                <div style={{ padding: '8px', backgroundColor: 'var(--surface-panel)', border: '1px solid var(--border-strong)', borderRadius: 'var(--radius-sm)' }}>
                  <div style={{ fontSize: '10.5px', color: 'var(--severity-critical-text)', fontWeight: 600 }}>Simulated Escalation</div>
                  <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--severity-critical-text)', marginTop: '2px' }}>
                    {whatIfResult.simulated_risk_score}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                    +{whatIfResult.simulated_risk_score - (incident?.risk_score || 80)} points
                  </div>
                </div>
              </div>

              <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', lineHeight: '1.4', paddingTop: '4px', borderTop: '1px solid var(--border-subtle)' }}>
                <strong>Impact shift:</strong> Next attacker step probability jumps to{' '}
                <strong style={{ color: 'var(--text-primary)' }}>{(whatIfResult.next_predicted_probability * 100).toFixed(1)}%</strong>. Immediate network isolation required.
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Tab: Analyst Feedback ── */}
      {activeTab === 'feedback' && (
        <div style={{ padding: '14px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div>
            <div style={{ fontWeight: 600, fontSize: '12.5px', color: 'var(--text-primary)' }}>
              Markov Dirichlet prior calibration
            </div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '2px' }}>
              Confirm or reject the model's correlation. Submitting updates transition weights online via conjugate Dirichlet update.
            </div>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              onClick={() => submitFeedback('accept')}
              className="btn-success"
              style={{ flex: 1, padding: '7px 10px', fontSize: '11.5px', justifyContent: 'center' }}
            >
              Confirm correlation
            </button>
            <button
              onClick={() => submitFeedback('reject')}
              className="btn-danger"
              style={{ flex: 1, padding: '7px 10px', fontSize: '11.5px', justifyContent: 'center' }}
            >
              Mark as false positive
            </button>
          </div>

          {feedbackStatus && (
            <div
              style={{
                padding: '8px 10px',
                backgroundColor: 'var(--surface-subtle)',
                border: '1px solid var(--border-default)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '11.5px',
                color: 'var(--text-secondary)',
              }}
            >
              {feedbackStatus}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
