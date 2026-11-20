/**
 * Incident Helper Utilities for H-SOC
 * Derives human-readable titles, extracts affected assets, and formats timestamps.
 */

export function getAffectedAsset(incident) {
  if (!incident || !incident.entity_keys || incident.entity_keys.length === 0) {
    return 'Unknown asset';
  }
  // Prioritize host, then ip, then user
  const host = incident.entity_keys.find((k) => k.startsWith('host:'));
  if (host) return host.replace('host:', '');

  const ip = incident.entity_keys.find((k) => k.startsWith('ip:'));
  if (ip) return ip.replace('ip:', '');

  const user = incident.entity_keys.find((k) => k.startsWith('user:'));
  if (user) return user.replace('user:', '');

  return incident.entity_keys[0].split(':')[1] || incident.entity_keys[0];
}

export function getHumanReadableTitle(incident) {
  if (!incident) return 'Security incident';

  const asset = getAffectedAsset(incident);
  const tactics = incident.tactics || [];
  const techniques = incident.techniques || [];

  // Check specific technique or timeline clues
  const timelineDesc = incident.timeline && incident.timeline[0]?.description;
  if (timelineDesc) {
    if (timelineDesc.toLowerCase().includes('probing') || timelineDesc.toLowerCase().includes('path probing')) {
      return `Web path probing and scan on ${asset}`;
    }
    if (timelineDesc.toLowerCase().includes('sudo') || timelineDesc.toLowerCase().includes('privilege')) {
      return `Privilege escalation via exploit on ${asset}`;
    }
    if (timelineDesc.toLowerCase().includes('failed login') || timelineDesc.toLowerCase().includes('brute force')) {
      return `Repeated failed logins, brute force on ${asset}`;
    }
  }

  // Tactic-based titles
  if (tactics.includes('privilege_escalation') && tactics.includes('initial_access')) {
    return `Initial access followed by privilege escalation on ${asset}`;
  }
  if (tactics.includes('initial_access') && tactics.includes('reconnaissance')) {
    return `External exploit and initial access on ${asset}`;
  }
  if (tactics.includes('credential_access')) {
    return `Brute-force credential access on ${asset}`;
  }
  if (tactics.includes('privilege_escalation')) {
    return `Unauthorized privilege escalation on ${asset}`;
  }
  if (tactics.includes('persistence')) {
    return `Persistence backdoor established on ${asset}`;
  }
  if (tactics.includes('reconnaissance')) {
    return `Reconnaissance and port scan on ${asset}`;
  }
  if (tactics.includes('exfiltration')) {
    return `Suspicious data exfiltration from ${asset}`;
  }

  if (tactics.length > 0) {
    const formatted = tactics[0].replace(/_/g, ' ');
    return `${formatted.charAt(0).toUpperCase() + formatted.slice(1)} detected on ${asset}`;
  }

  return `Suspicious activity on ${asset}`;
}

export function getTimeAgo(ts) {
  if (!ts) return 'just now';
  try {
    const date = new Date(ts);
    const now = new Date();
    const diffSec = Math.floor((now.getTime() - date.getTime()) / 1000);
    if (isNaN(diffSec)) return 'recent';
    if (diffSec < 60) return `${Math.max(1, diffSec)}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    const diffDays = Math.floor(diffHr / 24);
    return `${diffDays}d ago`;
  } catch {
    return 'recent';
  }
}

export const SEVERITY_CONFIG = {
  critical: {
    label: 'Critical',
    symbol: '◆',
    color: 'var(--severity-critical)',
    bg: 'var(--severity-critical-bg)',
    text: 'var(--severity-critical-text)',
    rank: 4,
  },
  high: {
    label: 'High',
    symbol: '▲',
    color: 'var(--severity-high)',
    bg: 'var(--severity-high-bg)',
    text: 'var(--severity-high-text)',
    rank: 3,
  },
  medium: {
    label: 'Medium',
    symbol: '●',
    color: 'var(--severity-medium)',
    bg: 'var(--severity-medium-bg)',
    text: 'var(--severity-medium-text)',
    rank: 2,
  },
  low: {
    label: 'Low',
    symbol: '■',
    color: 'var(--severity-low)',
    bg: 'var(--severity-low-bg)',
    text: 'var(--severity-low-text)',
    rank: 1,
  },
};
