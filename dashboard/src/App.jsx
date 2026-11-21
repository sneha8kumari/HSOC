import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Bot,
  Sun,
  Moon,
  SlidersHorizontal,
  Keyboard,
  Check,
  Play,
  Pause,
  Zap,
  Activity,
  Laptop,
  Server,
  RefreshCw,
  Radio,
  Filter
} from 'lucide-react';

import IncidentQueue from './components/IncidentQueue';
import CaseView from './components/CaseView';
import CopilotPanel from './components/CopilotPanel';
import CitationModal from './components/CitationModal';
import KeyboardShortcutsModal from './components/KeyboardShortcutsModal';
import TopNav from './components/TopNav';
import OverviewMetrics from './components/OverviewMetrics';

export default function App() {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [incidentDetail, setIncidentDetail] = useState(null);
  const [graphData, setGraphData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [isCopilotOpen, setIsCopilotOpen] = useState(true);
  const [theme, setTheme] = useState('dark');
  const [density, setDensity] = useState(() => localStorage.getItem('hsoc_density') || 'comfortable');
  const [isShortcutsOpen, setIsShortcutsOpen] = useState(false);
  const [actionDecision, setActionDecision] = useState(null);
  const [telemetryFilter, setTelemetryFilter] = useState('all'); // 'all' | 'live' | 'simulated'
  const [collectingWindows, setCollectingWindows] = useState(false);

  // Telemetry Health state
  const [telemetryHealth, setTelemetryHealth] = useState({
    status: 'checking',
    components: {
      streaming_pipeline: { status: 'ok' },
      windows_collector: { status: 'standby', enabled: true },
      wazuh_integration: { status: 'standby', enabled: false },
      ai_copilot: { provider: 'ollama', status: 'standby', model: 'llama3:8b' }
    }
  });

  // Real-time Live Stream state
  const [streamStatus, setStreamStatus] = useState({
    running: true,
    speed: 5,
    current_scenario_name: 'Live Pipeline + S8',
    events_emitted: 0,
  });
  const [lastLiveEvent, setLastLiveEvent] = useState(null);
  const [liveIncidentId, setLiveIncidentId] = useState(null);

  // Citation modal state
  const [modalCitation, setModalCitation] = useState({ type: null, id: null });

  // Sync density attribute to root
  useEffect(() => {
    document.documentElement.setAttribute('data-density', density);
    localStorage.setItem('hsoc_density', density);
  }, [density]);

  const fetchTelemetryHealth = async () => {
    try {
      const res = await fetch('/api/v1/telemetry/health');
      if (res.ok) {
        const data = await res.json();
        setTelemetryHealth(data);
      }
    } catch (e) {
      // offline
    }
  };

  useEffect(() => {
    fetchIncidents();
    fetchTelemetryHealth();
    const interval = setInterval(fetchTelemetryHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  // Connect to backend Server-Sent Events (SSE) live telemetry stream
  useEffect(() => {
    let es = null;
    try {
      es = new EventSource('/stream/live');
      es.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          if (data.type === 'connected') {
            setStreamStatus(data.status);
            if (data.status.active_incident_id) {
              setLiveIncidentId(data.status.active_incident_id);
            }
          } else if (data.type === 'event_ingested') {
            setLastLiveEvent(data);
          } else if (data.type === 'alert_created') {
            setLastLiveEvent({
              type: 'alert',
              ...data,
              target: data.entity_id,
            });
            fetchIncidents();
          } else if (data.type === 'incident_updated') {
            setLiveIncidentId(data.incident_id);
            setIncidents((prev) => {
              const idx = prev.findIndex((i) => i.incident_id === data.incident_id);
              if (idx !== -1) {
                const updated = [...prev];
                updated[idx] = {
                  ...updated[idx],
                  severity: data.severity,
                  risk_score: data.risk_score,
                  tactics: data.tactics || updated[idx].tactics,
                  techniques: data.techniques || updated[idx].techniques,
                  entity_keys: data.entity_keys || updated[idx].entity_keys,
                  is_simulated: data.is_simulated,
                  updated_at: data.updated_at,
                };
                return updated;
              } else {
                return [
                  {
                    incident_id: data.incident_id,
                    severity: data.severity,
                    risk_score: data.risk_score,
                    tactics: data.tactics || [],
                    techniques: data.techniques || [],
                    entity_keys: data.entity_keys || [],
                    is_simulated: data.is_simulated,
                    created_at: data.updated_at,
                    updated_at: data.updated_at,
                    status: data.status || 'open',
                  },
                  ...prev,
                ];
              }
            });
            if (selectedIncidentId === data.incident_id) {
              fetchIncidentDetail(selectedIncidentId);
            }
          } else if (data.type === 'attack_event') {
            setLastLiveEvent(data);
            if (data.incident) {
              const inc = data.incident;
              setLiveIncidentId(inc.incident_id);

              setIncidents((prev) => {
                let idx = prev.findIndex((i) => i.incident_id === inc.incident_id);
                if (idx === -1 && inc.target) {
                  // Fallback match by target asset / entity key
                  idx = prev.findIndex((i) =>
                    (i.entity_keys || []).some(
                      (k) =>
                        String(k).toLowerCase().includes(String(inc.target).toLowerCase()) ||
                        String(inc.target).toLowerCase().includes(String(k).toLowerCase())
                    )
                  );
                }

                if (idx !== -1) {
                  const updated = [...prev];
                  updated[idx] = {
                    ...updated[idx],
                    risk_score: inc.risk_score,
                    severity: inc.severity,
                    tactics: Array.from(new Set([...(updated[idx].tactics || []), inc.tactic])),
                    techniques: Array.from(new Set([...(updated[idx].techniques || []), inc.technique])),
                    updated_at: inc.updated_at,
                    out_of_order_stage: inc.out_of_order,
                    is_simulated: inc.is_simulated !== undefined ? inc.is_simulated : true,
                  };
                  return updated;
                } else {
                  return [
                    {
                      incident_id: inc.incident_id,
                      severity: inc.severity,
                      risk_score: inc.risk_score,
                      tactics: [inc.tactic],
                      techniques: [inc.technique],
                      entity_keys: [inc.target],
                      created_at: inc.updated_at,
                      updated_at: inc.updated_at,
                      out_of_order_stage: inc.out_of_order,
                      status: 'open',
                      is_simulated: inc.is_simulated !== undefined ? inc.is_simulated : true,
                    },
                    ...prev,
                  ];
                }
              });

              // If currently focused on this incident, refresh detail seamlessly
              if (selectedIncidentId === inc.incident_id) {
                fetchIncidentDetail(selectedIncidentId);
              }
            }
          } else if (data.type === 'benign_event') {
            setLastLiveEvent(data);
          }
        } catch (err) {
          console.error('SSE JSON error', err);
        }
      };
    } catch (err) {
      console.error('Failed to establish EventSource connection', err);
    }

    return () => {
      if (es) es.close();
    };
  }, [selectedIncidentId]);

  const fetchIncidents = async () => {
    try {
      const res = await fetch('/incidents');
      if (res.ok) {
        const data = await res.json();
        const rank = { critical: 4, high: 3, medium: 2, low: 1 };
        const sorted = [...data].sort((a, b) => {
          const rA = rank[a.severity] || 0;
          const rB = rank[b.severity] || 0;
          if (rB !== rA) return rB - rA;
          return (b.risk_score || 0) - (a.risk_score || 0);
        });
        setIncidents(sorted);
        if (sorted.length > 0 && !selectedIncidentId) {
          setSelectedIncidentId(sorted[0].incident_id);
        }
      }
    } catch (err) {
      console.error('Failed to load incidents', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!selectedIncidentId) return;
    setDetailLoading(true);
    setActionDecision(null);
    Promise.all([
      fetchIncidentDetail(selectedIncidentId),
      fetchGraphData(selectedIncidentId),
    ]).finally(() => setDetailLoading(false));
  }, [selectedIncidentId]);

  const fetchIncidentDetail = async (id) => {
    try {
      const res = await fetch(`/incidents/${id}`);
      if (res.ok) {
        const data = await res.json();
        setIncidentDetail(data);
      }
    } catch (err) {
      console.error('Failed to load incident detail', err);
    }
  };

  const fetchGraphData = async (id) => {
    try {
      const res = await fetch(`/incidents/${id}/graph`);
      if (res.ok) {
        const data = await res.json();
        setGraphData(data);
      }
    } catch (err) {
      console.error('Failed to load graph data', err);
    }
  };

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
  };

  const toggleDensity = () => {
    setDensity((prev) => (prev === 'comfortable' ? 'compact' : 'comfortable'));
  };

  // Real-time stream control handlers
  const handleToggleStream = async () => {
    try {
      const endpoint = streamStatus.running ? '/stream/pause' : '/stream/start';
      const res = await fetch(endpoint, { method: 'POST' });
      if (res.ok) {
        setStreamStatus((prev) => ({ ...prev, running: !prev.running }));
      }
    } catch (err) {
      console.error('Failed to toggle stream', err);
    }
  };

  const handleSetSpeed = async (speed) => {
    try {
      const res = await fetch('/stream/speed', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ speed }),
      });
      if (res.ok) {
        setStreamStatus((prev) => ({ ...prev, speed }));
      }
    } catch (err) {
      console.error('Failed to set speed', err);
    }
  };

  const handleInjectAttack = async () => {
    try {
      const res = await fetch('/stream/inject', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario_id: 'S8' }),
      });
      if (res.ok) {
        const data = await res.json();
        setStreamStatus(data.engine);
        fetchIncidents();
      }
    } catch (err) {
      console.error('Failed to inject attack step', err);
    }
  };

  const handleCollectWindows = async () => {
    setCollectingWindows(true);
    try {
      const res = await fetch('/api/v1/telemetry/windows/collect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ max_events: 50, collect_network: true }),
      });
      if (res.ok) {
        await res.json();
        fetchIncidents();
        fetchTelemetryHealth();
      }
    } catch (e) {
      console.error('Failed to collect Windows telemetry', e);
    } finally {
      setCollectingWindows(false);
    }
  };

  const selectedIncident = incidents.find((i) => i.incident_id === selectedIncidentId);

  // Keyboard navigation & shortcuts
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Don't trigger if user is typing in an input
      if (['INPUT', 'TEXTAREA'].includes(e.target.tagName)) return;

      if (e.key === 'j' || e.key === 'k') {
        const currentIdx = incidents.findIndex((i) => i.incident_id === selectedIncidentId);
        if (currentIdx === -1) return;

        if (e.key === 'j' && currentIdx < incidents.length - 1) {
          setSelectedIncidentId(incidents[currentIdx + 1].incident_id);
        } else if (e.key === 'k' && currentIdx > 0) {
          setSelectedIncidentId(incidents[currentIdx - 1].incident_id);
        }
      } else if (e.key === 'Enter') {
        const casePanel = document.querySelector('main');
        if (casePanel) casePanel.focus?.();
      } else if (e.key === 'a' || e.key === 'A') {
        setActionDecision('approved');
      } else if (e.key === 'r' || e.key === 'R') {
        setActionDecision('rejected');
      } else if (e.key === 'd' || e.key === 'D') {
        toggleDensity();
      } else if (e.key === 't' || e.key === 'T') {
        toggleTheme();
      } else if (e.key === 'c' || e.key === 'C') {
        setIsCopilotOpen((prev) => !prev);
      } else if (e.key === '?') {
        setIsShortcutsOpen(true);
      } else if (e.key === 'Escape') {
        setIsShortcutsOpen(false);
        setModalCitation({ type: null, id: null });
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [incidents, selectedIncidentId, theme, density]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', width: '100vw', overflow: 'hidden' }}>
      {/* ── Top Navigation Bar ── */}
      <TopNav
        streamStatus={streamStatus}
        onToggleStream={handleToggleStream}
        onSetSpeed={handleSetSpeed}
        onInjectAttack={handleInjectAttack}
        telemetryHealth={telemetryHealth}
        collectingWindows={collectingWindows}
        onCollectWindows={handleCollectWindows}
        density={density}
        onToggleDensity={toggleDensity}
        theme={theme}
        onToggleTheme={toggleTheme}
        onOpenShortcuts={() => setIsShortcutsOpen(true)}
        isCopilotOpen={isCopilotOpen}
        onToggleCopilot={() => setIsCopilotOpen((prev) => !prev)}
      />

      {/* ── Modern Overview Metrics ── */}
      <OverviewMetrics
        incidents={incidents}
        streamStatus={streamStatus}
        telemetryHealth={telemetryHealth}
      />

      {/* ── 3-Column Layout: Queue (Left) -> Case (Center) -> Assistant (Right) ── */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {/* Left: Compact Sortable Incident Queue */}
        <IncidentQueue
          incidents={incidents}
          selectedIncidentId={selectedIncidentId}
          onSelectIncident={(id) => setSelectedIncidentId(id)}
          loading={loading}
          liveIncidentId={liveIncidentId}
          telemetryFilter={telemetryFilter}
          onOpenShortcuts={() => setIsShortcutsOpen(true)}
        />

        {/* Center: Case Investigation View */}
        <CaseView
          incident={selectedIncident}
          incidentDetail={incidentDetail}
          graphData={graphData}
          loading={detailLoading}
          externalActionStatus={actionDecision}
          onActionDecision={(s) => setActionDecision(s)}
          liveIncidentId={liveIncidentId}
          lastLiveEvent={lastLiveEvent}
          onOpenChunk={(chunkId) => setModalCitation({ type: 'chunk', id: chunkId })}
          onOpenEvidence={(evidenceId) => setModalCitation({ type: 'evidence', id: evidenceId })}
          onRefreshIncident={() => {
            fetchIncidents();
            if (selectedIncidentId) fetchIncidentDetail(selectedIncidentId);
          }}
        />

        {/* Right: Collapsible Assistant Drawer (Copilot / What-if / Feedback) */}
        {isCopilotOpen && (
          <aside
            aria-label="AI Copilot and case assistant"
            style={{
              width: '380px',
              minWidth: '320px',
              maxWidth: '440px',
              borderLeft: '1px solid var(--border-default)',
              backgroundColor: 'var(--surface-panel)',
              display: 'flex',
              flexDirection: 'column',
              height: '100%',
            }}
          >
            <CopilotPanel
              incident={incidentDetail || selectedIncident}
              onRefreshIncident={() => {
                fetchIncidents();
                if (selectedIncidentId) fetchIncidentDetail(selectedIncidentId);
              }}
              onOpenChunk={(chunkId) => setModalCitation({ type: 'chunk', id: chunkId })}
              onOpenEvidence={(evidenceId) => setModalCitation({ type: 'evidence', id: evidenceId })}
            />
          </aside>
        )}
      </div>

      {/* ── Evidence / Knowledge Chunk Modal ── */}
      {modalCitation.id && (
        <CitationModal
          type={modalCitation.type}
          id={modalCitation.id}
          incident={incidentDetail || selectedIncident}
          onClose={() => setModalCitation({ type: null, id: null })}
        />
      )}

      {/* ── Keyboard Shortcuts Cheat Sheet Modal ── */}
      <KeyboardShortcutsModal
        isOpen={isShortcutsOpen}
        onClose={() => setIsShortcutsOpen(false)}
      />
    </div>
  );
}
