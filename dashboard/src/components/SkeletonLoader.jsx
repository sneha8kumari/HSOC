import React from 'react';

/**
 * Reusable loading skeletons with gentle, low-contrast shimmer.
 * Prevents layout shift and replaces spinners with structured wireframe silhouettes.
 */
export function QueueSkeleton({ count = 5 }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          style={{
            padding: 'var(--density-queue-pad, 9px 12px 9px 14px)',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            flexDirection: 'column',
            gap: '6px',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div className="skeleton skeleton-bar" style={{ width: `${60 + (i % 3) * 15}%`, height: '13px' }} />
            <div className="skeleton skeleton-bar" style={{ width: '24px', height: '13px' }} />
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <div className="skeleton skeleton-bar" style={{ width: '12px', height: '10px' }} />
            <div className="skeleton skeleton-bar" style={{ width: '80px', height: '10px' }} />
            <div className="skeleton skeleton-bar" style={{ width: '60px', height: '10px' }} />
          </div>
        </div>
      ))}
    </div>
  );
}

export function CaseViewSkeleton() {
  return (
    <div style={{ padding: 'var(--density-case-pad, 16px 20px)', display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Summary Banner Skeleton */}
      <div
        style={{
          padding: 'var(--density-banner-pad, 12px 16px)',
          backgroundColor: 'var(--surface-panel)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-sm)',
          display: 'flex',
          flexDirection: 'column',
          gap: '10px',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
          <div className="skeleton skeleton-bar" style={{ width: '45%', height: '16px' }} />
          <div className="skeleton skeleton-bar" style={{ width: '15%', height: '14px' }} />
        </div>
        <div className="skeleton skeleton-bar" style={{ width: '85%', height: '12px' }} />
        <div className="skeleton skeleton-bar" style={{ width: '65%', height: '12px' }} />
        <div style={{ display: 'flex', gap: '8px', marginTop: '4px' }}>
          <div className="skeleton skeleton-bar" style={{ width: '90px', height: '24px' }} />
          <div className="skeleton skeleton-bar" style={{ width: '70px', height: '24px' }} />
        </div>
      </div>

      {/* Timeline Steps Skeleton */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        <div className="skeleton skeleton-bar" style={{ width: '140px', height: '14px' }} />
        {Array.from({ length: 3 }).map((_, i) => (
          <div
            key={i}
            style={{
              padding: '12px 14px',
              backgroundColor: 'var(--surface-panel)',
              border: '1px solid var(--border-default)',
              borderRadius: 'var(--radius-sm)',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <div className="skeleton skeleton-bar" style={{ width: '40%', height: '13px' }} />
              <div className="skeleton skeleton-bar" style={{ width: '80px', height: '11px' }} />
            </div>
            <div className="skeleton skeleton-bar" style={{ width: '70%', height: '11px' }} />
          </div>
        ))}
      </div>
    </div>
  );
}

export function MarkovSkeleton() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      <div
        style={{
          padding: '16px',
          backgroundColor: 'var(--surface-panel)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-sm)',
          display: 'flex',
          flexDirection: 'column',
          gap: '10px',
        }}
      >
        <div className="skeleton skeleton-bar" style={{ width: '60%', height: '16px' }} />
        <div className="skeleton skeleton-bar" style={{ width: '85%', height: '12px' }} />
        <div style={{ display: 'flex', gap: '10px', marginTop: '6px' }}>
          <div className="skeleton skeleton-bar" style={{ width: '110px', height: '36px' }} />
          <div className="skeleton skeleton-bar" style={{ width: '110px', height: '36px' }} />
          <div className="skeleton skeleton-bar" style={{ width: '110px', height: '36px' }} />
        </div>
      </div>
      <div
        style={{
          padding: '16px',
          backgroundColor: 'var(--surface-panel)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-sm)',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
        }}
      >
        <div className="skeleton skeleton-bar" style={{ width: '40%', height: '14px' }} />
        <div className="skeleton skeleton-bar" style={{ width: '100%', height: '80px' }} />
      </div>
    </div>
  );
}

export function AgentTracesSkeleton() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      <div
        style={{
          padding: '14px 18px',
          backgroundColor: 'var(--surface-panel)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-sm)',
          display: 'flex',
          justifyContent: 'space-between',
        }}
      >
        <div className="skeleton skeleton-bar" style={{ width: '180px', height: '14px' }} />
        <div className="skeleton skeleton-bar" style={{ width: '90px', height: '14px' }} />
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            style={{
              padding: '12px',
              backgroundColor: 'var(--surface-panel)',
              border: '1px solid var(--border-default)',
              borderRadius: 'var(--radius-sm)',
            }}
          >
            <div className="skeleton skeleton-bar" style={{ width: `${50 + (i % 2) * 20}%`, height: '12px' }} />
          </div>
        ))}
      </div>
    </div>
  );
}
