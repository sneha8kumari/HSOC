import React from 'react';
import {
  ShieldAlert,
  Bot,
  Sun,
  Moon,
  SlidersHorizontal,
  Keyboard,
  Play,
  Pause,
  Zap,
  Laptop,
  Server,
  Radio,
  RefreshCw,
} from 'lucide-react';

export default function TopNav({
  streamStatus = {},
  onToggleStream,
  onSetSpeed,
  onInjectAttack,
  telemetryHealth = {},
  collectingWindows,
  onCollectWindows,
  density,
  onToggleDensity,
  theme,
  onToggleTheme,
  onOpenShortcuts,
  isCopilotOpen,
  onToggleCopilot,
}) {
  return (
    <header
      role="banner"
      style={{
        height: '52px',
        backgroundColor: '#0a0f1d',
        borderBottom: '1px solid rgba(56, 189, 248, 0.15)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 18px',
        flexShrink: 0,
        boxShadow: '0 2px 10px rgba(0, 0, 0, 0.35)',
      }}
    >
      {/* ── Left: H-SOC Logo & Brand Badge ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '32px',
            height: '32px',
            background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.2) 0%, rgba(139, 92, 246, 0.25) 100%)',
            border: '1px solid rgba(0, 240, 255, 0.4)',
            borderRadius: '8px',
            boxShadow: '0 0 12px rgba(0, 240, 255, 0.25)',
          }}
        >
          <ShieldAlert size={18} style={{ color: '#00f0ff' }} />
        </div>
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              style={{
                fontWeight: 800,
                fontSize: '15px',
                letterSpacing: '1px',
                background: 'linear-gradient(90deg, #ffffff 0%, #00f0ff 100%)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
              }}
            >
              H-SOC
            </span>
            <span
              style={{
                fontSize: '9.5px',
                fontWeight: 700,
                padding: '1px 6px',
                borderRadius: '4px',
                background: 'rgba(16, 185, 129, 0.15)',
                color: '#10b981',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                letterSpacing: '0.5px',
              }}
            >
              OPERATIONAL
            </span>
          </div>
          <span style={{ fontSize: '11px', color: '#64748b', letterSpacing: '0.2px' }}>
            Hybrid Security Operations Center
          </span>
        </div>
      </div>

      {/* ── Center: Stream Controls & Scenario Engine ── */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          padding: '4px 12px',
          backgroundColor: 'rgba(15, 23, 42, 0.8)',
          borderRadius: '8px',
          border: '1px solid rgba(56, 189, 248, 0.2)',
          boxShadow: 'inset 0 1px 3px rgba(0, 0, 0, 0.3)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '11.5px' }}>
          <span
            style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              backgroundColor: streamStatus.running ? '#10b981' : '#f59e0b',
              boxShadow: streamStatus.running ? '0 0 8px #10b981' : 'none',
            }}
          />
          <span style={{ fontWeight: 600, color: '#f1f5f9' }}>
            {streamStatus.running ? 'Live' : 'Paused'}:
          </span>
          <span style={{ color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>
            {streamStatus.current_scenario_name || 'Active S1–S5 Pipeline'}
          </span>
        </div>

        <button
          onClick={onToggleStream}
          title={streamStatus.running ? 'Pause real-time stream' : 'Resume real-time stream'}
          className="btn-secondary"
          style={{
            padding: '3px 8px',
            fontSize: '11px',
            backgroundColor: streamStatus.running ? 'rgba(244, 63, 94, 0.15)' : 'rgba(16, 185, 129, 0.15)',
            borderColor: streamStatus.running ? 'rgba(244, 63, 94, 0.4)' : 'rgba(16, 185, 129, 0.4)',
            color: streamStatus.running ? '#ff8899' : '#34d399',
          }}
        >
          {streamStatus.running ? <Pause size={11} /> : <Play size={11} />}
          <span>{streamStatus.running ? 'Pause' : 'Play'}</span>
        </button>

        <div style={{ display: 'flex', gap: '2px', backgroundColor: 'rgba(30, 41, 59, 0.6)', padding: '2px', borderRadius: '4px' }}>
          {[1, 5, 10].map((s) => (
            <button
              key={s}
              onClick={() => onSetSpeed(s)}
              style={{
                padding: '2px 7px',
                fontSize: '10.5px',
                fontWeight: streamStatus.speed === s ? 700 : 400,
                backgroundColor: streamStatus.speed === s ? '#0284c7' : 'transparent',
                color: streamStatus.speed === s ? '#ffffff' : '#94a3b8',
                border: 'none',
                borderRadius: '3px',
                cursor: 'pointer',
              }}
            >
              {s}x
            </button>
          ))}
        </div>

        <button
          onClick={onInjectAttack}
          title="Inject an immediate attack scenario step"
          className="btn-secondary"
          style={{
            padding: '3px 9px',
            fontSize: '11px',
            backgroundColor: 'rgba(249, 115, 22, 0.15)',
            borderColor: 'rgba(249, 115, 22, 0.4)',
            color: '#fb923c',
            display: 'flex',
            alignItems: 'center',
            gap: '4px',
          }}
        >
          <Zap size={11} />
          <span>Inject Step</span>
        </button>
      </div>

      {/* ── Right: Telemetry Snapshots + System Controls ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        {/* Windows Telemetry Button */}
        <button
          onClick={onCollectWindows}
          disabled={collectingWindows}
          title="Collect immediate snapshot of Windows Event Logs & active network connections"
          className="btn-secondary"
          style={{
            padding: '4px 9px',
            fontSize: '11px',
            backgroundColor: 'rgba(56, 189, 248, 0.12)',
            borderColor: 'rgba(56, 189, 248, 0.3)',
            color: '#38bdf8',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '5px',
          }}
        >
          <Laptop size={12} />
          <span>{collectingWindows ? 'Polling Host...' : 'Scan Host'}</span>
          <RefreshCw size={10} className={collectingWindows ? 'spin' : ''} />
        </button>

        {/* Wazuh Indicator */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '5px',
            fontSize: '11px',
            color: '#94a3b8',
            padding: '3px 8px',
            backgroundColor: 'rgba(30, 41, 59, 0.5)',
            borderRadius: '6px',
            border: '1px solid rgba(51, 65, 85, 0.5)',
          }}
        >
          <Server size={12} color="#10b981" />
          <span>Wazuh:</span>
          <span style={{ color: '#10b981', fontWeight: 600 }}>READY</span>
        </div>

        <span style={{ color: 'rgba(51, 65, 85, 0.8)' }}>|</span>

        {/* Theme Toggle */}
        <button
          onClick={onToggleTheme}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode (Shortcut: t)`}
          className="btn-secondary"
          style={{ padding: '4px 8px', fontSize: '11.5px', color: '#94a3b8' }}
        >
          {theme === 'dark' ? <Sun size={13} color="#f59e0b" /> : <Moon size={13} />}
          <span>{theme === 'dark' ? 'Light' : 'Dark'}</span>
        </button>

        {/* Keyboard Shortcuts Guide */}
        <button
          onClick={onOpenShortcuts}
          title="Keyboard shortcuts cheat sheet (Shortcut: ?)"
          className="btn-secondary"
          style={{ padding: '4px 8px', fontSize: '11.5px', color: '#94a3b8' }}
        >
          <Keyboard size={13} />
          <span>Keys</span>
        </button>

        {/* Assistant Sidebar Toggle */}
        <button
          onClick={onToggleCopilot}
          title="Toggle Copilot drawer (Shortcut: c)"
          className="btn-secondary"
          style={{
            padding: '4px 10px',
            fontSize: '11.5px',
            backgroundColor: isCopilotOpen ? 'rgba(168, 85, 247, 0.2)' : 'transparent',
            borderColor: isCopilotOpen ? 'rgba(168, 85, 247, 0.5)' : 'var(--border-default)',
            color: isCopilotOpen ? '#c084fc' : '#94a3b8',
            display: 'flex',
            alignItems: 'center',
            gap: '5px',
            boxShadow: isCopilotOpen ? '0 0 10px rgba(168, 85, 247, 0.25)' : 'none',
          }}
        >
          <Bot size={13} />
          <span>{isCopilotOpen ? 'AI Assistant' : 'Open AI'}</span>
        </button>
      </div>
    </header>
  );
}
