import React, { useState, useEffect, useRef } from 'react';
import { Play, Pause, RotateCcw, FastForward, Clock, AlertTriangle, Shield, CheckCircle, Radio } from 'lucide-react';

export default function ReplayTimeline({ incidentId, timeline = [], onSelectEvent }) {
  const [replayData, setReplayData] = useState(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentStepIdx, setCurrentStepIdx] = useState(0);
  const [playbackSpeed, setPlaybackSpeed] = useState(10); // Default 10x as specified!
  const timerRef = useRef(null);

  useEffect(() => {
    if (!incidentId) return;
    fetchReplayData();
    setIsPlaying(false);
    setCurrentStepIdx(0);
  }, [incidentId]);

  const fetchReplayData = async () => {
    try {
      const res = await fetch(`/incidents/${incidentId}/replay`);
      if (res.ok) {
        const data = await res.json();
        setReplayData(data);
      }
    } catch (e) {
      console.error('Failed to load replay data', e);
    }
  };

  useEffect(() => {
    if (isPlaying) {
      const steps = replayData?.steps || [];
      if (currentStepIdx >= steps.length) {
        setIsPlaying(false);
        return;
      }

      // Interval scaled by playbackSpeed (10x means 200ms per event step)
      const intervalMs = Math.max(50, 1000 / playbackSpeed);
      timerRef.current = setTimeout(() => {
        setCurrentStepIdx((prev) => prev + 1);
      }, intervalMs);
    }
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [isPlaying, currentStepIdx, playbackSpeed, replayData]);

  const steps = replayData?.steps || [];
  const activeStep = steps[currentStepIdx] || steps[steps.length - 1];

  const handleReset = () => {
    setIsPlaying(false);
    setCurrentStepIdx(0);
  };

  return (
    <div className="glass-panel" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* Replay Controls Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span className="pulse-dot" style={{ background: isPlaying ? 'var(--accent-crimson)' : 'var(--text-muted)' }}></span>
            <span style={{ fontWeight: 700, fontSize: '13px', letterSpacing: '0.5px', color: '#fff' }}>
              SCENARIO TELEMETRY REPLAY
            </span>
          </div>
          <span style={{ padding: '2px 8px', borderRadius: '4px', background: 'rgba(0, 240, 255, 0.15)', color: 'var(--accent-cyan)', fontSize: '11px', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
            {playbackSpeed}x SPEED (LIVE DEMO)
          </span>
        </div>

        {/* Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className="btn-primary"
            style={{ padding: '6px 14px', fontSize: '12px' }}
          >
            {isPlaying ? <Pause size={14} /> : <Play size={14} />}
            {isPlaying ? 'Pause Replay' : 'Play Scenario'}
          </button>
          <button
            onClick={handleReset}
            className="btn-secondary"
            style={{ padding: '6px 12px', fontSize: '12px' }}
          >
            <RotateCcw size={14} /> Reset
          </button>
          <div style={{ display: 'flex', background: 'rgba(0,0,0,0.3)', borderRadius: '6px', padding: '2px', border: '1px solid var(--border-subtle)' }}>
            {[1, 5, 10].map((spd) => (
              <button
                key={spd}
                onClick={() => setPlaybackSpeed(spd)}
                style={{
                  background: playbackSpeed === spd ? 'var(--accent-cyan)' : 'none',
                  color: playbackSpeed === spd ? '#070a13' : 'var(--text-muted)',
                  border: 'none',
                  borderRadius: '4px',
                  padding: '3px 8px',
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 600,
                }}
              >
                {spd}x
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Progress scrubber bar */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
          <span>Event {Math.min(currentStepIdx + 1, steps.length)} of {steps.length}</span>
          <span>T + {activeStep?.offset_seconds || 0}s</span>
        </div>
        <div
          onClick={(e) => {
            const rect = e.currentTarget.getBoundingClientRect();
            const pct = (e.clientX - rect.left) / rect.width;
            setCurrentStepIdx(Math.floor(pct * steps.length));
          }}
          style={{ width: '100%', height: '8px', background: 'rgba(255,255,255,0.06)', borderRadius: '4px', cursor: 'pointer', position: 'relative', overflow: 'hidden' }}
        >
          <div
            style={{
              width: `${(steps.length ? (currentStepIdx / steps.length) * 100 : 0)}%`,
              height: '100%',
              background: 'linear-gradient(90deg, #00f0ff, #8b5cf6)',
              borderRadius: '4px',
              transition: 'width 0.1s linear',
            }}
          />
        </div>
      </div>

      {/* Live Flashing Event Terminal */}
      {activeStep && (
        <div style={{ background: '#050814', border: '1px solid rgba(0, 240, 255, 0.3)', borderRadius: '6px', padding: '10px 14px', fontFamily: 'var(--font-mono)', fontSize: '11.5px', color: '#38bdf8', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '85%' }}>
            <span style={{ color: 'var(--text-muted)' }}>[{activeStep.timestamp ? activeStep.timestamp.split('T')[1]?.slice(0, 8) : '00:00:00'}]</span>{' '}
            <span style={{ color: '#fff' }}>{activeStep.raw}</span>
          </div>
          {activeStep.triggered_alert && (
            <span style={{ padding: '2px 6px', borderRadius: '4px', background: 'rgba(244, 63, 94, 0.2)', border: '1px solid #f43f5e', color: '#fb7185', fontSize: '10px', fontWeight: 600 }}>
              Triggered Alert
            </span>
          )}
        </div>
      )}

      {/* Attack Timeline with Out-of-Order Stage Highlights */}
      <div>
        <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '8px' }}>
          Correlated Kill-Chain Progression Timeline
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {timeline.map((item, idx) => (
            <div
              key={idx}
              className={item.out_of_order ? 'out-of-order-pill' : ''}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '10px 14px',
                background: item.out_of_order ? undefined : 'rgba(15, 23, 42, 0.6)',
                border: item.out_of_order ? undefined : '1px solid var(--border-subtle)',
                borderRadius: '8px',
                fontSize: '12px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span className="font-mono text-cyan" style={{ fontWeight: 600 }}>
                  #{idx + 1}
                </span>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span style={{ fontWeight: 600, color: '#fff', textTransform: 'capitalize' }}>
                      {item.tactic ? item.tactic.replace('_', ' ') : 'Observed Stage'}
                    </span>
                    {item.technique && (
                      <span className="font-mono text-purple" style={{ fontSize: '11px' }}>
                        ({item.technique})
                      </span>
                    )}
                    {item.out_of_order && (
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '3px', background: 'rgba(239, 68, 68, 0.3)', border: '1px solid #ef4444', color: '#fef08a', padding: '1px 6px', borderRadius: '4px', fontSize: '10px', fontWeight: 700 }}>
                        <AlertTriangle size={11} /> OUT-OF-ORDER STAGE
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                    Alert ID: <span className="font-mono">{item.alert_id}</span> • {item.ts ? new Date(item.ts).toLocaleTimeString() : 'Recent'}
                  </div>
                </div>
              </div>

              <div>
                <span className="badge-medium" style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '11px' }}>
                  Stage {idx + 1}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
