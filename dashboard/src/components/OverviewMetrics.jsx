import React from 'react';
import { ShieldAlert, AlertTriangle, AlertCircle, ShieldCheck, Server, Radio, Bot, Activity } from 'lucide-react';

export default function OverviewMetrics({ incidents = [], streamStatus = {}, telemetryHealth = {} }) {
  const total = incidents.length;
  const critical = incidents.filter((i) => i.severity === 'critical').length;
  const high = incidents.filter((i) => i.severity === 'high').length;
  const medium = incidents.filter((i) => i.severity === 'medium').length;
  const low = incidents.filter((i) => i.severity === 'low').length;

  // Extract unique hosts & IPs
  const allEntities = new Set();
  incidents.forEach((i) => {
    (i.entity_keys || []).forEach((e) => allEntities.add(e));
  });
  const assetCount = Math.max(allEntities.size, 4);

  const metrics = [
    {
      id: 'total',
      label: 'TOTAL INCIDENTS',
      value: total,
      sub: `${critical} Critical · ${high} High`,
      icon: <Activity size={18} color="#38bdf8" />,
      accentColor: '#38bdf8',
      bgGradient: 'linear-gradient(135deg, rgba(56, 189, 248, 0.12) 0%, rgba(15, 23, 42, 0.6) 100%)',
      borderColor: 'rgba(56, 189, 248, 0.3)',
    },
    {
      id: 'critical',
      label: 'CRITICAL THREATS',
      value: critical,
      sub: 'Immediate action required',
      icon: <ShieldAlert size={18} color="#f43f5e" />,
      accentColor: '#f43f5e',
      bgGradient: 'linear-gradient(135deg, rgba(244, 63, 94, 0.14) 0%, rgba(15, 23, 42, 0.6) 100%)',
      borderColor: 'rgba(244, 63, 94, 0.35)',
      isDanger: critical > 0,
    },
    {
      id: 'high',
      label: 'HIGH RISK CASES',
      value: high,
      sub: `${medium} medium · ${low} low`,
      icon: <AlertTriangle size={18} color="#f97316" />,
      accentColor: '#f97316',
      bgGradient: 'linear-gradient(135deg, rgba(249, 115, 22, 0.12) 0%, rgba(15, 23, 42, 0.6) 100%)',
      borderColor: 'rgba(249, 115, 22, 0.3)',
    },
    {
      id: 'assets',
      label: 'MONITORED ASSETS',
      value: assetCount,
      sub: 'Hosts & Network Endpoints',
      icon: <Server size={18} color="#10b981" />,
      accentColor: '#10b981',
      bgGradient: 'linear-gradient(135deg, rgba(16, 185, 129, 0.12) 0%, rgba(15, 23, 42, 0.6) 100%)',
      borderColor: 'rgba(16, 185, 129, 0.3)',
    },
    {
      id: 'stream',
      label: 'CEP EVENT STREAM',
      value: streamStatus.running ? 'STREAMING' : 'PAUSED',
      sub: `${streamStatus.speed || 5}x playback · ${streamStatus.current_scenario_name || 'Active S1-S5'}`,
      icon: <Radio size={18} color="#00f0ff" className={streamStatus.running ? 'pulse-live' : ''} />,
      accentColor: '#00f0ff',
      bgGradient: 'linear-gradient(135deg, rgba(0, 240, 255, 0.12) 0%, rgba(15, 23, 42, 0.6) 100%)',
      borderColor: 'rgba(0, 240, 255, 0.3)',
      isText: true,
    },
    {
      id: 'copilot',
      label: 'AI COPILOT RAG',
      value: telemetryHealth.components?.ai_copilot?.provider === 'ollama' ? 'OLLAMA' : 'HYBRID RAG',
      sub: 'Markov Predictor + Citations',
      icon: <Bot size={18} color="#a855f7" />,
      accentColor: '#a855f7',
      bgGradient: 'linear-gradient(135deg, rgba(168, 85, 247, 0.12) 0%, rgba(15, 23, 42, 0.6) 100%)',
      borderColor: 'rgba(168, 85, 247, 0.3)',
      isText: true,
    },
  ];

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: '12px',
        padding: '12px 16px',
        backgroundColor: 'rgba(10, 15, 26, 0.7)',
        borderBottom: '1px solid var(--border-default)',
        flexShrink: 0,
      }}
    >
      {metrics.map((m) => (
        <div
          key={m.id}
          style={{
            background: m.bgGradient,
            border: `1px solid ${m.borderColor}`,
            borderRadius: '10px',
            padding: '10px 14px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '10px',
            boxShadow: '0 4px 12px rgba(0, 0, 0, 0.25)',
            transition: 'transform 0.15s ease, border-color 0.15s ease',
          }}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', minWidth: 0 }}>
            <span
              style={{
                fontSize: '10px',
                fontWeight: 600,
                letterSpacing: '0.6px',
                color: 'var(--text-muted)',
              }}
            >
              {m.label}
            </span>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
              <span
                style={{
                  fontSize: m.isText ? '14px' : '20px',
                  fontWeight: 700,
                  fontFamily: 'var(--font-mono)',
                  color: m.accentColor,
                  letterSpacing: '-0.3px',
                }}
              >
                {m.value}
              </span>
              {m.isDanger && (
                <span
                  style={{
                    fontSize: '9px',
                    fontWeight: 700,
                    padding: '1px 5px',
                    borderRadius: '4px',
                    backgroundColor: 'rgba(244, 63, 94, 0.25)',
                    color: '#ff8899',
                    border: '1px solid rgba(244, 63, 94, 0.4)',
                  }}
                >
                  ACTIVE
                </span>
              )}
            </div>
            <span
              style={{
                fontSize: '10.5px',
                color: 'var(--text-secondary)',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}
            >
              {m.sub}
            </span>
          </div>

          <div
            style={{
              width: '36px',
              height: '36px',
              borderRadius: '8px',
              backgroundColor: 'rgba(15, 23, 42, 0.8)',
              border: `1px solid ${m.borderColor}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
              boxShadow: `0 0 10px ${m.borderColor}`,
            }}
          >
            {m.icon}
          </div>
        </div>
      ))}
    </div>
  );
}
