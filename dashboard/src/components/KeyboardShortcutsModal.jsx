import React, { useEffect } from 'react';
import { X, Keyboard } from 'lucide-react';

export default function KeyboardShortcutsModal({ isOpen, onClose }) {
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const shortcutGroups = [
    {
      group: 'Queue Navigation',
      items: [
        { keys: ['j'], desc: 'Move to next incident in queue' },
        { keys: ['k'], desc: 'Move to previous incident in queue' },
        { keys: ['Enter'], desc: 'Open / focus selected incident' },
      ],
    },
    {
      group: 'Analyst Decisions',
      items: [
        { keys: ['a'], desc: 'Approve recommended remediation step' },
        { keys: ['r'], desc: 'Reject recommended remediation step' },
      ],
    },
    {
      group: 'Workspace & Display',
      items: [
        { keys: ['d'], desc: 'Toggle density (Comfortable / Compact)' },
        { keys: ['t'], desc: 'Toggle theme (Dark / Light)' },
        { keys: ['c'], desc: 'Toggle Copilot assistant drawer' },
        { keys: ['?'], desc: 'Open this keyboard shortcuts guide' },
        { keys: ['Esc'], desc: 'Close dialog or modal' },
      ],
    },
  ];

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="shortcuts-heading"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.65)',
        zIndex: 150,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px',
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: '540px',
          maxWidth: '92vw',
          backgroundColor: 'var(--surface-panel)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-lg)',
          boxShadow: 'var(--shadow-overlay)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            padding: '12px 18px',
            borderBottom: '1px solid var(--border-default)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Keyboard size={16} style={{ color: 'var(--text-secondary)' }} />
            <h2 id="shortcuts-heading" style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
              Keyboard shortcuts
            </h2>
          </div>
          <button
            onClick={onClose}
            className="btn-secondary"
            aria-label="Close keyboard shortcuts dialog"
            style={{ padding: '3px 6px', border: 'none' }}
          >
            <X size={15} />
          </button>
        </div>

        {/* Content */}
        <div style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
          {shortcutGroups.map((grp) => (
            <div key={grp.group} style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                {grp.group}
              </span>
              <div
                style={{
                  backgroundColor: 'var(--surface-subtle)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  overflow: 'hidden',
                }}
              >
                {grp.items.map((item, idx) => (
                  <div
                    key={idx}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '7px 12px',
                      borderBottom: idx < grp.items.length - 1 ? '1px solid var(--border-subtle)' : 'none',
                      fontSize: '12px',
                    }}
                  >
                    <span style={{ color: 'var(--text-primary)' }}>{item.desc}</span>
                    <div style={{ display: 'flex', gap: '4px' }}>
                      {item.keys.map((k) => (
                        <kbd
                          key={k}
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: '11px',
                            fontWeight: 600,
                            padding: '2px 7px',
                            backgroundColor: 'var(--surface-panel)',
                            border: '1px solid var(--border-strong)',
                            borderRadius: 'var(--radius-sm)',
                            color: 'var(--text-primary)',
                            boxShadow: '0 1px 2px rgba(0,0,0,0.2)',
                          }}
                        >
                          {k}
                        </kbd>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '10px 18px',
            borderTop: '1px solid var(--border-subtle)',
            backgroundColor: 'var(--surface-canvas)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            fontSize: '11px',
            color: 'var(--text-muted)',
          }}
        >
          <span>Shortcuts are disabled while focused on text inputs.</span>
          <button onClick={onClose} className="btn-primary" style={{ padding: '3px 10px', fontSize: '11px' }}>
            Got it
          </button>
        </div>
      </div>
    </div>
  );
}
