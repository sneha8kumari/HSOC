import React, { useState, useEffect, useRef } from 'react';
import { Network, Server, ShieldAlert, User, Globe, ZoomIn, ZoomOut, RotateCcw, Info } from 'lucide-react';

export default function AttackGraph({ incidentId, graphData, onSelectNode }) {
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const containerRef = useRef(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  useEffect(() => {
    if (!graphData || !graphData.nodes) return;

    const width = containerRef.current ? containerRef.current.clientWidth : 750;
    const height = containerRef.current ? containerRef.current.clientHeight : 440;

    // Position nodes using radial / multi-stage structured layout with ample spacing
    const positionedNodes = graphData.nodes.map((node, i) => {
      let x = width / 2;
      let y = height / 2;

      if (node.type === 'incident') {
        x = width * 0.16;
        y = height / 2;
      } else if (node.type === 'alert') {
        const alertIndex = graphData.nodes.filter(n => n.type === 'alert').indexOf(node);
        const totalAlerts = graphData.nodes.filter(n => n.type === 'alert').length || 1;
        x = width * 0.48;
        y = (height * 0.16) + (alertIndex * ((height * 0.68) / Math.max(1, totalAlerts - 1 || 1)));
      } else if (node.type.startsWith('entity_')) {
        const entIndex = graphData.nodes.filter(n => n.type.startsWith('entity_')).indexOf(node);
        const totalEnts = graphData.nodes.filter(n => n.type.startsWith('entity_')).length || 1;
        x = width * 0.84;
        y = (height * 0.18) + (entIndex * ((height * 0.64) / Math.max(1, totalEnts - 1 || 1)));
      }

      return {
        ...node,
        x,
        y,
      };
    });

    setNodes(positionedNodes);
    setEdges(graphData.edges || []);
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }, [graphData]);

  const getNodeColor = (type, severity) => {
    if (type === 'incident') return '#a855f7';
    if (type === 'alert') {
      if (severity === 'critical') return '#f43f5e';
      if (severity === 'high') return '#f97316';
      if (severity === 'medium') return '#eab308';
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

  const handleNodeClick = (node, e) => {
    e.stopPropagation();
    setSelectedNodeId(node.id);
    if (onSelectNode) onSelectNode(node);
  };

  const handleMouseDown = (e) => {
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e) => {
    if (!isDragging) return;
    setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleZoomIn = () => setZoom(prev => Math.min(prev + 0.2, 2.5));
  const handleZoomOut = () => setZoom(prev => Math.max(prev - 0.2, 0.5));
  const handleResetZoom = () => { setZoom(1); setPan({ x: 0, y: 0 }); };

  return (
    <div
      className="glass-panel"
      style={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        position: 'relative',
        overflow: 'hidden',
        backgroundColor: '#090d18',
        borderRadius: '10px',
        border: '1px solid rgba(56, 189, 248, 0.2)',
      }}
      ref={containerRef}
    >
      {/* ── Header bar with Legend & Zoom Controls ── */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '12px 18px',
          borderBottom: '1px solid var(--border-default)',
          backgroundColor: 'rgba(15, 23, 42, 0.85)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Network size={18} style={{ color: '#00f0ff' }} />
          <span style={{ fontWeight: 700, fontSize: '13px', letterSpacing: '0.5px', color: '#f8fafc' }}>
            ATTACK CORRELATION GRAPH
          </span>
          <span style={{ fontSize: '11px', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
            ({nodes.length} nodes · {edges.length} edges)
          </span>
        </div>

        {/* Legend */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', fontSize: '11px' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '5px', color: '#cbd5e1' }}>
            <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#a855f7', boxShadow: '0 0 6px #a855f7' }}></span> Incident
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '5px', color: '#cbd5e1' }}>
            <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#f43f5e', boxShadow: '0 0 6px #f43f5e' }}></span> Alert Stage
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '5px', color: '#cbd5e1' }}>
            <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#38bdf8', boxShadow: '0 0 6px #38bdf8' }}></span> Host
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '5px', color: '#cbd5e1' }}>
            <span style={{ width: 9, height: 9, borderRadius: '50%', background: '#ec4899', boxShadow: '0 0 6px #ec4899' }}></span> Attacker IP
          </span>
        </div>

        {/* Zoom Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <button
            onClick={handleZoomIn}
            title="Zoom In"
            className="btn-secondary"
            style={{ padding: '3px 7px', fontSize: '11px' }}
          >
            <ZoomIn size={13} />
          </button>
          <button
            onClick={handleZoomOut}
            title="Zoom Out"
            className="btn-secondary"
            style={{ padding: '3px 7px', fontSize: '11px' }}
          >
            <ZoomOut size={13} />
          </button>
          <button
            onClick={handleResetZoom}
            title="Reset Zoom & Pan"
            className="btn-secondary"
            style={{ padding: '3px 8px', fontSize: '11px' }}
          >
            <RotateCcw size={12} />
            <span>Reset</span>
          </button>
        </div>
      </div>

      {/* ── Interactive SVG Canvas with Zoom & Pan ── */}
      <div
        style={{
          flex: 1,
          position: 'relative',
          minHeight: '380px',
          cursor: isDragging ? 'grabbing' : 'grab',
          userSelect: 'none',
        }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <svg width="100%" height="100%" style={{ overflow: 'visible' }}>
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="rgba(56, 189, 248, 0.85)" />
            </marker>
          </defs>

          {/* Transform group for Pan and Zoom */}
          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            {/* Render Edges */}
            {edges.map((edge, idx) => {
              const srcNode = nodes.find(n => n.id === edge.source);
              const tgtNode = nodes.find(n => n.id === edge.target);
              if (!srcNode || !tgtNode) return null;

              const isProgression = edge.relation === 'tactic_progression';
              const strokeColor = isProgression ? '#00f0ff' : 'rgba(148, 163, 184, 0.35)';
              const strokeWidth = isProgression ? 2.5 : 1.3;
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
                    opacity={0.85}
                    markerEnd={isProgression ? 'url(#arrow)' : undefined}
                  />
                  {edge.label && (
                    <text
                      x={midX}
                      y={midY - 4}
                      fill="#94a3b8"
                      fontSize="10px"
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
              const radius = node.type === 'incident' ? 24 : (node.type === 'alert' ? 18 : 15);

              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  onClick={(e) => handleNodeClick(node, e)}
                  style={{ cursor: 'pointer' }}
                >
                  {/* Glowing Halo */}
                  <circle
                    r={radius + (isSelected ? 9 : 4)}
                    fill={color}
                    opacity={isSelected ? 0.4 : 0.15}
                  />
                  {/* Node Circle */}
                  <circle
                    r={radius}
                    fill="#0c1224"
                    stroke={color}
                    strokeWidth={isSelected ? 3 : 2}
                    style={{ filter: isSelected ? `drop-shadow(0 0 12px ${color})` : 'none' }}
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
                    y={radius + 16}
                    fill={isSelected ? '#ffffff' : '#cbd5e1'}
                    fontSize="11.5px"
                    fontFamily="var(--font-sans)"
                    fontWeight={isSelected ? 700 : 500}
                    textAnchor="middle"
                  >
                    {node.label}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>

        {/* Selected Node Details Drawer */}
        {selectedNodeId && (() => {
          const selNode = nodes.find(n => n.id === selectedNodeId);
          if (!selNode) return null;
          return (
            <div
              style={{
                position: 'absolute',
                bottom: '14px',
                right: '14px',
                width: '300px',
                background: 'rgba(15, 23, 42, 0.95)',
                backdropFilter: 'blur(10px)',
                border: '1px solid rgba(56, 189, 248, 0.4)',
                borderRadius: '10px',
                padding: '14px',
                fontSize: '12px',
                boxShadow: '0 8px 24px rgba(0, 0, 0, 0.6)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                <span style={{ fontWeight: 700, color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '5px' }}>
                  <Info size={14} /> Node Telemetry
                </span>
                <button
                  onClick={() => setSelectedNodeId(null)}
                  style={{ background: 'none', border: 'none', color: '#94a3b8', fontSize: '14px', cursor: 'pointer' }}
                >
                  ✕
                </button>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <div><span style={{ color: '#64748b' }}>ID:</span> <span className="font-mono text-cyan">{selNode.id}</span></div>
                <div><span style={{ color: '#64748b' }}>Type:</span> <span style={{ textTransform: 'capitalize' }}>{selNode.type}</span></div>
                {selNode.technique && <div><span style={{ color: '#64748b' }}>Technique:</span> <span className="font-mono" style={{ color: '#f97316' }}>{selNode.technique}</span></div>}
                {selNode.tactic && <div><span style={{ color: '#64748b' }}>Tactic:</span> <span style={{ textTransform: 'capitalize', color: '#c084fc' }}>{selNode.tactic}</span></div>}
                {selNode.conf !== undefined && <div><span style={{ color: '#64748b' }}>Confidence:</span> <span style={{ color: '#10b981', fontWeight: 600 }}>{(selNode.conf * 100).toFixed(0)}%</span></div>}
                {selNode.val && <div><span style={{ color: '#64748b' }}>Value:</span> <span className="font-mono">{selNode.val}</span></div>}
              </div>
            </div>
          );
        })()}
      </div>
    </div>
  );
}
