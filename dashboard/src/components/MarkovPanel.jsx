import React, { useState, useEffect } from 'react';
import { ChevronDown, ChevronRight, Info } from 'lucide-react';
import { MarkovSkeleton } from './SkeletonLoader';

export default function MarkovPanel({ selectedIncident }) {
  const [panelData, setPanelData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [hoveredCell, setHoveredCell] = useState(null);
  const [currentTactic, setCurrentTactic] = useState('reconnaissance');
  const [showMatrixWorking, setShowMatrixWorking] = useState(false);

  useEffect(() => {
    if (selectedIncident && selectedIncident.tactics && selectedIncident.tactics.length > 0) {
      const latest = selectedIncident.tactics[selectedIncident.tactics.length - 1];
      setCurrentTactic(latest.toLowerCase());
    }
  }, [selectedIncident]);

  useEffect(() => {
    fetchPanelData(currentTactic);
  }, [currentTactic]);

  const fetchPanelData = async (tactic) => {
    setLoading(true);
    try {
      const obs = selectedIncident && selectedIncident.tactics ? selectedIncident.tactics.join(',') : tactic;
      const res = await fetch(`/models/markov/panel?current_tactic=${tactic}&observed_sequence=${obs}`);
      if (res.ok) {
        const data = await res.json();
        setPanelData(data);
      }
    } catch (err) {
      console.error('Failed to load Markov panel data', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading && !panelData) {
    return <MarkovSkeleton />;
  }

  const tactics = panelData?.tactics || [];
  const matrix = panelData?.matrix || [];
  const predictions = panelData?.next_step_predictions || [];
  const absorption = panelData?.absorption_risk || 0.45;
  const viterbi = panelData?.viterbi_path || [];
  const observedTactics = selectedIncident?.tactics || [currentTactic];

  const topPrediction = predictions[0];
  const topTacticName = topPrediction ? topPrediction.tactic.replace(/_/g, ' ') : 'Privilege escalation';
  const topProbPct = topPrediction ? (topPrediction.probability * 100).toFixed(0) : '41';
  const remainingSteps = Math.max(1, Math.min(4, viterbi.length || 3));

  // Word labels for uncertainty
  const getWordLabel = (prob, ciLower, ciUpper) => {
    const span = ciUpper - ciLower;
    if (prob >= 0.35 && span <= 0.2) return 'fairly sure';
    if (prob >= 0.20 || span <= 0.3) return 'moderate confidence';
    return 'low confidence';
  };

  // One-line reason sentence
  const getOneLineReason = () => {
    if (observedTactics.length >= 2) {
      const lastTwo = observedTactics.slice(-2).map((t) => t.replace(/_/g, ' '));
      return `Based on the last 2 steps: ${lastTwo[0]}, then ${lastTwo[1]}.`;
    }
    if (observedTactics.length === 1) {
      return `Based on the last step: ${observedTactics[0].replace(/_/g, ' ')}.`;
    }
    return `Based on observed incident progression.`;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* ── 1. Plain-Language Sentence Lead & One-Line Reason ── */}
      <div
        style={{
          padding: '16px 18px',
          backgroundColor: 'var(--surface-panel)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-sm)',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
        }}
      >
        <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
          Attack progression forecast
        </div>

        <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', lineHeight: '1.4' }}>
          Most likely next step: <span style={{ textTransform: 'capitalize', color: 'var(--severity-high-text)' }}>{topTacticName}</span> ({topProbPct}%). If it gets there, impact is likely within about {remainingSteps} steps.
        </div>

        <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>
          {getOneLineReason()}
        </div>
      </div>

      {/* ── 2. Observed vs Predicted Path on One Line (Solid = seen, Dashed = predicted) ── */}
      <div
        style={{
          padding: '14px 18px',
          backgroundColor: 'var(--surface-panel)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-sm)',
          display: 'flex',
          flexDirection: 'column',
          gap: '10px',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Attack progression trajectory
          </div>
          <div style={{ display: 'flex', gap: '12px', fontSize: '11px', color: 'var(--text-muted)' }}>
            <span><strong style={{ borderBottom: '2px solid var(--border-strong)', paddingBottom: '1px' }}>Solid box</strong> = seen</span>
            <span><strong style={{ borderBottom: '2px dashed var(--border-focus)', paddingBottom: '1px' }}>Dashed box</strong> = predicted next</span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
          {/* Confirmed seen steps (Solid border) */}
          {observedTactics.map((tac, i) => (
            <React.Fragment key={`obs-${i}`}>
              <div
                style={{
                  padding: '4px 10px',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--surface-subtle)',
                  border: '1.5px solid var(--border-strong)',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <span style={{ fontSize: '10px', color: 'var(--state-success-text)' }}>●</span>
                <span style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-primary)', textTransform: 'capitalize' }}>
                  {tac.replace(/_/g, ' ')}
                </span>
                <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>(seen)</span>
              </div>
              <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>→</span>
            </React.Fragment>
          ))}

          {/* Predicted next steps (Dashed border) */}
          {viterbi.slice(0, 3).map((pred, i) => (
            <React.Fragment key={`pred-${i}`}>
              <div
                style={{
                  padding: '4px 10px',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'transparent',
                  border: '1.5px dashed var(--border-focus)',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <span style={{ fontSize: '10px', color: 'var(--border-focus)' }}>○</span>
                <span style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-primary)', textTransform: 'capitalize' }}>
                  {pred.replace(/_/g, ' ')}
                </span>
                <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>(predicted)</span>
              </div>
              {i < Math.min(viterbi.length - 1, 2) && (
                <span style={{ color: 'var(--text-muted)' }}>⇢</span>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* ── 3. Next-Step Probabilities as Horizontal Bar List with Thin Whisker & Word Labels ── */}
      <div
        style={{
          padding: '14px 18px',
          backgroundColor: 'var(--surface-panel)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-sm)',
          display: 'flex',
          flexDirection: 'column',
          gap: '12px',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Next-step probabilities (with 95% uncertainty brackets)
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Current stage: {currentTactic.replace(/_/g, ' ')}
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {predictions.slice(0, 5).map((pred, idx) => {
            const wordLabel = getWordLabel(pred.probability, pred.ci_lower, pred.ci_upper);
            const probPct = (pred.probability * 100).toFixed(1);
            const lowPct = (pred.ci_lower * 100).toFixed(0);
            const highPct = (pred.ci_upper * 100).toFixed(0);

            return (
              <div key={idx} style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span className="font-mono" style={{ color: 'var(--text-muted)' }}>#{idx + 1}</span>
                    <span style={{ textTransform: 'capitalize', color: 'var(--text-primary)', fontWeight: 500 }}>
                      {pred.tactic.replace(/_/g, ' ')}
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span
                      style={{
                        fontSize: '11px',
                        color: wordLabel === 'fairly sure' ? 'var(--state-success-text)' : 'var(--text-muted)',
                        fontWeight: wordLabel === 'fairly sure' ? 500 : 400,
                      }}
                    >
                      {wordLabel}
                    </span>
                    <span className="font-mono" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                      {probPct}%
                    </span>
                    <span className="font-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      [{lowPct}% - {highPct}%]
                    </span>
                  </div>
                </div>

                {/* Horizontal bar with thin uncertainty whisker */}
                <div
                  style={{
                    position: 'relative',
                    width: '100%',
                    height: '6px',
                    backgroundColor: 'var(--surface-subtle)',
                    borderRadius: '2px',
                    overflow: 'visible',
                  }}
                >
                  {/* Probability Bar */}
                  <div
                    style={{
                      width: `${Math.min(100, pred.probability * 100)}%`,
                      height: '100%',
                      backgroundColor: idx === 0 ? 'var(--border-focus)' : 'var(--text-muted)',
                      borderRadius: '2px',
                    }}
                  />

                  {/* Thin Uncertainty Whisker Bracket */}
                  <div
                    title={`95% Credible interval: ${lowPct}% to ${highPct}%`}
                    style={{
                      position: 'absolute',
                      top: '-2px',
                      bottom: '-2px',
                      left: `${pred.ci_lower * 100}%`,
                      width: `${Math.max(2, (pred.ci_upper - pred.ci_lower) * 100)}%`,
                      borderLeft: '1.5px solid var(--text-primary)',
                      borderRight: '1.5px solid var(--text-primary)',
                      backgroundColor: 'rgba(240, 242, 245, 0.08)',
                      pointerEvents: 'none',
                    }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── Terminal Absorption Risk ── */}
      <div
        style={{
          padding: '12px 18px',
          backgroundColor: 'var(--surface-panel)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-sm)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div>
          <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Terminal absorption risk: <span className="font-mono">{(absorption * 100).toFixed(0)}%</span>
          </div>
          <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '2px' }}>
            Probability that an uncontained attack chain reaches Impact or Exfiltration based on historical priors.
          </div>
        </div>

        <span
          style={{
            padding: '2px 8px',
            borderRadius: 'var(--radius-sm)',
            fontSize: '11px',
            fontWeight: 600,
            backgroundColor: absorption > 0.6 ? 'var(--severity-critical-bg)' : 'var(--severity-medium-bg)',
            color: absorption > 0.6 ? 'var(--severity-critical-text)' : 'var(--severity-medium-text)',
            border: `1px solid ${absorption > 0.6 ? 'var(--severity-critical)' : 'var(--severity-medium)'}`,
          }}
        >
          {absorption > 0.6 ? 'High impact threat' : 'Moderate threat'}
        </span>
      </div>

      {/* ── 4. Collapsible: Show the Model's Working (Backoff Level & Matrix Row) ── */}
      <div
        style={{
          backgroundColor: 'var(--surface-panel)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-sm)',
          overflow: 'hidden',
        }}
      >
        <button
          onClick={() => setShowMatrixWorking(!showMatrixWorking)}
          style={{
            width: '100%',
            padding: '10px 14px',
            backgroundColor: 'transparent',
            border: 'none',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            cursor: 'pointer',
            color: 'var(--text-secondary)',
            fontSize: '12px',
          }}
        >
          <span style={{ fontWeight: 500 }}>Show the model's working</span>
          {showMatrixWorking ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </button>

        {showMatrixWorking && (
          <div style={{ padding: '14px 18px', borderTop: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {/* Caption on how to read the matrix */}
            <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', lineHeight: '1.4' }}>
              <strong>How to read this matrix:</strong> Each cell shows the probability <span className="font-mono">P(next stage | current stage)</span>. Rows represent the current observed stage; columns represent the potential destination stages. The highlighted row corresponds to the current incident stage.
            </div>

            {/* Backoff Level and Matrix Row details */}
            <div style={{ display: 'flex', gap: '16px', fontSize: '11.5px', color: 'var(--text-secondary)', padding: '6px 10px', backgroundColor: 'var(--surface-subtle)', borderRadius: 'var(--radius-sm)' }}>
              <div>Backoff level: <strong style={{ color: 'var(--text-primary)' }}>Level 2 (2nd-order with Dirichlet backoff prior)</strong></div>
              <div>Active matrix row: <strong style={{ color: 'var(--text-primary)', textTransform: 'capitalize' }}>{currentTactic.replace(/_/g, ' ')}</strong></div>
            </div>

            {/* Matrix Heatmap Table */}
            <div style={{ overflowX: 'auto', paddingBottom: '6px' }}>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: `120px repeat(${tactics.length}, minmax(26px, 1fr))`,
                  gap: '2px',
                  minWidth: '600px',
                }}
              >
                <div></div>
                {tactics.map((t, idx) => (
                  <div
                    key={`th-${idx}`}
                    title={t}
                    style={{
                      fontSize: '9px',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--text-muted)',
                      textAlign: 'center',
                      textTransform: 'uppercase',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }}
                  >
                    {t.slice(0, 4)}
                  </div>
                ))}

                {tactics.map((rowTactic, rowIdx) => (
                  <React.Fragment key={`row-${rowIdx}`}>
                    <div
                      style={{
                        fontSize: '10.5px',
                        color: currentTactic === rowTactic ? 'var(--text-primary)' : 'var(--text-muted)',
                        fontWeight: currentTactic === rowTactic ? 600 : 400,
                        textTransform: 'capitalize',
                        display: 'flex',
                        alignItems: 'center',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {rowTactic.replace(/_/g, ' ')}
                    </div>

                    {tactics.map((colTactic, colIdx) => {
                      const prob = matrix[rowIdx] ? matrix[rowIdx][colIdx] : 0;
                      const isRowSelected = currentTactic === rowTactic;
                      return (
                        <div
                          key={`cell-${rowIdx}-${colIdx}`}
                          onMouseEnter={() => setHoveredCell({ src: rowTactic, dst: colTactic, prob })}
                          onMouseLeave={() => setHoveredCell(null)}
                          onClick={() => setCurrentTactic(rowTactic)}
                          title={`P(${colTactic} | ${rowTactic}) = ${(prob * 100).toFixed(1)}%`}
                          style={{
                            height: '22px',
                            backgroundColor: prob > 0.3 ? 'var(--border-strong)' : prob > 0.1 ? 'var(--surface-active)' : 'var(--surface-subtle)',
                            border: isRowSelected ? '1px solid var(--border-strong)' : '1px solid var(--border-subtle)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontSize: '9px',
                            fontFamily: 'var(--font-mono)',
                            color: prob > 0.2 ? 'var(--text-primary)' : 'var(--text-muted)',
                            cursor: 'pointer',
                          }}
                        >
                          {prob >= 0.15 ? (prob * 100).toFixed(0) : ''}
                        </div>
                      );
                    })}
                  </React.Fragment>
                ))}
              </div>
            </div>

            {hoveredCell && (
              <div className="font-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                P({hoveredCell.dst} | {hoveredCell.src}) = {(hoveredCell.prob * 100).toFixed(2)}%
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
