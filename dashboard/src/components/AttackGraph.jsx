import React, { useState, useEffect, useRef } from 'react';
import { Network, Server, ShieldAlert, User, Globe, Maximize2, RefreshCw } from 'lucide-react';

export default function AttackGraph({ incidentId, graphData, onSelectNode }) {
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const containerRef = useRef(null);
  const [dimensions, setDimensions] = useState({ width: 700, height: 420 });

  useEffect(() => {
    if (!graphData || !graphData.nodes) return;

    const width = containerRef.current ? containerRef.current.clientWidth : 700;
    const height = containerRef.current ? containerRef.current.clientHeight : 420;
    setDimensions({ width, height });

    // Position nodes using force-like radial / staged layout
    const positionedNodes = graphData.nodes.map((node, i) => {
      let x = width / 2;
      let y = height / 2;

      if (node.type === 'incident') {
        x = width * 0.18;
        y = height / 2;
      } else if (node.type === 'alert') {
        const alertIndex = graphData.nodes.filter(n => n.type === 'alert').indexOf(node);
        const totalAlerts = graphData.nodes.filter(n => n.type === 'alert').length || 1;
        x = width * 0.45;
        y = (height * 0.18) + (alertIndex * ((height * 0.65) / Math.max(1, totalAlerts - 1 || 1)));
      } else if (node.type.startsWith('entity_')) {
        const entIndex = graphData.nodes.filter(n => n.type.startsWith('entity_')).indexOf(node);
        const totalEnts = graphData.nodes.filter(n => n.type.startsWith('entity_')).length || 1;
        x = width * 0.82;
        y = (height * 0.2) + (entIndex * ((height * 0.6) / Math.max(1, totalEnts - 1 || 1)));
      }

      // Add gentle jitter for aesthetic spacing
      const jitterX = (Math.sin(i * 1.5) * 12);
      const jitterY = (Math.cos(i * 1.5) * 12);

      return {
        ...node,
        x: x + jitterX,
        y: y + jitterY,
      };
    });

    setNodes(positionedNodes);
    setEdges(graphData.edges || []);
  }, [graphData]);

  const getNodeColor = (type, severity) => {
    if (type === 'incident') return '#8b5cf6';
    if (type === 'alert') {
      if (severity === 'critical') return '#ff0055';
      if (severity === 'high') return '#f43f5e';
      if (severity === 'medium') return '#f59e0b';
      return '#00f0ff';
    }
    if (type === 'entity_host') return '#38bdf8';
    if (type === 'entity_ip') return '#ec4899';
    if (type === 'entity_user') return '#10b981';
    return '#64748b';
  };

  const getNodeIcon = (type) => {
    if (type === 'incident') return <Network size={16} color="#fff" />;
    if (type === 'alert') return <ShieldAlert size={15} color="#fff" />;
    if (type === 'entity_host') return <Server size={14} color="#fff" />;
    if (type === 'entity_ip') return <Globe size={14} color="#fff" />;
    if (type === 'entity_user') return <User size={14} color="#fff" />;
    return null;
  };

  const handleNodeClick = (node) => {
    setSelectedNodeId(node.id);
    if (onSelectNode) onSelectNode(node);
  };

  return (
    <div className="glass-panel" style={{ height: '100%', display: 'flex', flexDirection: 'column', position: 'relative', overflow: 'hidden' }} ref={containerRef}>
      {/* Header bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 18px', borderBottom: '1px solid var(--border-subtle)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Network size={18} className="text-cyan" />
          <span style={{ fontWeight: 600, fontSize: '13px', letterSpacing: '0.5px' }}>INTERACTIVE ATTACK CORRELATION GRAPH</span>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>({nodes.length} nodes, {edges.length} edges)</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', fontSize: '11px' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><span style={{ width: 8, height: 8, borderRadius: '50%', background: '#8b5cf6' }}></span> Incident</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><span style={{ width: 8, height: 8, borderRadius: '50%', background: '#f43f5e' }}></span> Alert Stage</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><span style={{ width: 8, height: 8, borderRadius: '50%', background: '#38bdf8' }}></span> Host Target</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><span style={{ width: 8, height: 8, borderRadius: '50%', background: '#ec4899' }}></span> Attacker IP</span>
        </div>
      </div>

      {/* SVG Canvas */}
      <div style={{ flex: 1, position: 'relative', minHeight: '360px' }}>
        <svg width="100%" height="100%" style={{ overflow: 'visible' }}>
          <defs>
            <filter id="glow-edge" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
            <linearGradient id="edge-grad-recon" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#00f0ff" stopOpacity="0.7" />
              <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0.8" />
            </linearGradient>
            <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="rgba(56, 189, 248, 0.7)" />
            </marker>
          </defs>

          {/* Render Edges */}
          {edges.map((edge, idx) => {
            const srcNode = nodes.find(n => n.id === edge.source);
            const tgtNode = nodes.find(n => n.id === edge.target);
            if (!srcNode || !tgtNode) return null;

            const isProgression = edge.relation === 'tactic_progression';
            const strokeColor = isProgression ? '#00f0ff' : 'rgba(148, 163, 184, 0.3)';
            const strokeWidth = isProgression ? 2.5 : 1.2;
            const strokeDash = isProgression ? '4,4' : 'none';

            // Curved quadratic Bezier path
            const midX = (srcNode.x + tgtNode.x) / 2;
            const midY = (srcNode.y + tgtNode.y) / 2 + (isProgression ? -25 : 10);
            const pathData = `M ${srcNode.x} ${srcNode.y} Q ${midX} ${midY} ${tgtNode.x} ${tgtNode.y}`;

            return (
              <g key={`edge-${idx}`}>
                <path
                  d={pathData}
                  fill="none"
                  stroke={strokeColor}
                  strokeWidth={strokeWidth}
                  strokeDasharray={strokeDash}
                  opacity={0.8}
                  markerEnd={isProgression ? 'url(#arrow)' : undefined}
                />
                {edge.label && (
                  <text
                    x={midX}
                    y={midY - 4}
                    fill="var(--text-muted)"
                    fontSize="9.5px"
                    fontFamily="var(--font-mono)"
                    textAnchor="middle"
                  >
                    {edge.label}
                  </text>
                )}
              </g>
            );
          })}

          {/* Render Nodes */}
          {nodes.map((node) => {
            const isSelected = selectedNodeId === node.id;
            const color = getNodeColor(node.type, node.severity);
            const radius = node.type === 'incident' ? 24 : (node.type === 'alert' ? 18 : 14);

            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                onClick={() => handleNodeClick(node)}
                style={{ cursor: 'pointer' }}
              >
                {/* Outer Glow Halo */}
                <circle
                  r={radius + (isSelected ? 8 : 4)}
                  fill={color}
                  opacity={isSelected ? 0.35 : 0.12}
                />
                {/* Node Body */}
                <circle
                  r={radius}
                  fill="#0c1224"
                  stroke={color}
                  strokeWidth={isSelected ? 3 : 2}
                  style={{ filter: isSelected ? 'drop-shadow(0 0 12px ' + color + ')' : 'none' }}
                />
                {/* Centered Icon */}
                <foreignObject
                  x={-radius}
                  y={-radius}
                  width={radius * 2}
                  height={radius * 2}
                  style={{ pointerEvents: 'none' }}
                >
                  <div style={{ width: '100%', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    {getNodeIcon(node.type)}
                  </div>
                </foreignObject>
                {/* Label */}
                <text
                  y={radius + 15}
                  fill={isSelected ? '#fff' : 'var(--text-secondary)'}
                  fontSize="11px"
                  fontFamily="var(--font-sans)"
                  fontWeight={isSelected ? 600 : 400}
                  textAnchor="middle"
                >
                  {node.label}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Selected Node Details overlay drawer */}
        {selectedNodeId && (() => {
          const selNode = nodes.find(n => n.id === selectedNodeId);
          if (!selNode) return null;
          return (
            <div
              style={{
                position: 'absolute',
                bottom: '12px',
                right: '12px',
                width: '280px',
                background: 'rgba(15, 23, 42, 0.95)',
                border: '1px solid var(--border-glow)',
                borderRadius: '8px',
                padding: '12px',
                fontSize: '12px',
                boxShadow: '0 8px 24px rgba(0,0,0,0.5)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>Node Telemetry</span>
                <button
                  onClick={() => setSelectedNodeId(null)}
                  style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '13px' }}
                >
                  ✕
                </button>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div><span style={{ color: 'var(--text-muted)' }}>ID:</span> <span className="font-mono text-cyan">{selNode.id}</span></div>
                <div><span style={{ color: 'var(--text-muted)' }}>Type:</span> <span>{selNode.type}</span></div>
                {selNode.technique && <div><span style={{ color: 'var(--text-muted)' }}>Technique:</span> <span className="font-mono">{selNode.technique}</span></div>}
                {selNode.tactic && <div><span style={{ color: 'var(--text-muted)' }}>Tactic:</span> <span style={{ textTransform: 'capitalize' }}>{selNode.tactic}</span></div>}
                {selNode.conf !== undefined && <div><span style={{ color: 'var(--text-muted)' }}>Confidence:</span> <span>{(selNode.conf * 100).toFixed(0)}%</span></div>}
                {selNode.val && <div><span style={{ color: 'var(--text-muted)' }}>Value:</span> <span className="font-mono">{selNode.val}</span></div>}
              </div>
            </div>
          );
        })()}
      </div>
    </div>
  );
}
