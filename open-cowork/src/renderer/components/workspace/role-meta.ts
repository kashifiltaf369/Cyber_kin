import type { InvestigationAgentRole } from '../../../main/investigation/parallel-investigation-engine';
import type {
  InvestigationEvidence,
  InvestigationHypothesis,
  InvestigationTask,
} from '../../../shared/cyber/investigation-types';
import {
  Monitor,
  Network,
  User,
  Radar,
  History,
  FlaskConical,
  Search,
  Swords,
  Cpu,
  Globe2,
  Fingerprint,
  ShieldAlert,
  ScrollText,
  type LucideIcon,
} from 'lucide-react';

export interface RoleDescriptor {
  role: InvestigationAgentRole;
  shortLabel: string;
  icon: LucideIcon;
  accent: string;
  accentMuted: string;
}

export const ROLE_DESCRIPTORS: Record<InvestigationAgentRole, RoleDescriptor> = {
  'Endpoint Investigator': {
    role: 'Endpoint Investigator',
    shortLabel: 'Endpoint',
    icon: Monitor,
    accent: '#38BDF8',
    accentMuted: 'rgba(56, 189, 248, 0.16)',
  },
  'Network Investigator': {
    role: 'Network Investigator',
    shortLabel: 'Network',
    icon: Network,
    accent: '#60A5FA',
    accentMuted: 'rgba(96, 165, 250, 0.16)',
  },
  'Identity Investigator': {
    role: 'Identity Investigator',
    shortLabel: 'Identity',
    icon: User,
    accent: '#A78BFA',
    accentMuted: 'rgba(167, 139, 250, 0.16)',
  },
  'Threat Intelligence Investigator': {
    role: 'Threat Intelligence Investigator',
    shortLabel: 'Threat Intel',
    icon: Radar,
    accent: '#FB7185',
    accentMuted: 'rgba(251, 113, 133, 0.16)',
  },
  'Historical Investigator': {
    role: 'Historical Investigator',
    shortLabel: 'Historical',
    icon: History,
    accent: '#F5B942',
    accentMuted: 'rgba(245, 185, 66, 0.16)',
  },
  'Evidence Analyst': {
    role: 'Evidence Analyst',
    shortLabel: 'Analyst',
    icon: FlaskConical,
    accent: '#34D399',
    accentMuted: 'rgba(52, 211, 153, 0.16)',
  },
  'Research Investigator': {
    role: 'Research Investigator',
    shortLabel: 'Research',
    icon: Search,
    accent: '#8B7CFF',
    accentMuted: 'rgba(139, 124, 255, 0.16)',
  },
  Challenger: {
    role: 'Challenger',
    shortLabel: 'Challenger',
    icon: Swords,
    accent: '#F05252',
    accentMuted: 'rgba(240, 82, 82, 0.16)',
  },
};

export function getRoleDescriptor(role: InvestigationAgentRole): RoleDescriptor {
  return (
    ROLE_DESCRIPTORS[role] ?? {
      role,
      shortLabel: role,
      icon: Cpu,
      accent: '#7F8994',
      accentMuted: 'rgba(127, 137, 148, 0.16)',
    }
  );
}

export function entityIcon(type: string): LucideIcon {
  switch (type) {
    case 'ip':
      return Network;
    case 'domain':
      return Globe2;
    case 'host':
      return Cpu;
    case 'user':
      return User;
    case 'process':
      return Cpu;
    case 'url':
      return Globe2;
    case 'hash':
      return Fingerprint;
    case 'account':
      return Fingerprint;
    case 'file':
      return ScrollText;
    case 'service':
      return ShieldAlert;
    case 'alert':
      return ShieldAlert;
    case 'event':
      return ScrollText;
    default:
      return ScrollText;
  }
}

export type WorkerStatus =
  | 'queued'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'blocked'
  | 'unknown';

export function statusFromTask(task: InvestigationTask | undefined): WorkerStatus {
  if (!task) return 'unknown';
  switch (task.status) {
    case 'CREATED':
      return 'queued';
    case 'STARTED':
      return 'running';
    case 'PAUSED':
      return 'paused';
    case 'COMPLETED':
      return 'completed';
    case 'CANCELLED':
      return 'cancelled';
    case 'BLOCKED':
      return 'blocked';
    default:
      return 'unknown';
  }
}

export const STATUS_LABEL: Record<WorkerStatus, string> = {
  queued: 'Queued',
  running: 'Investigating',
  paused: 'Paused',
  completed: 'Complete',
  failed: 'Failed',
  cancelled: 'Cancelled',
  blocked: 'Blocked',
  unknown: 'Waiting',
};

export const STATUS_COLOR: Record<WorkerStatus, string> = {
  queued: 'var(--soc-text-muted)',
  running: 'var(--soc-accent-primary)',
  paused: 'var(--soc-warning-main)',
  completed: 'var(--soc-success-main)',
  failed: 'var(--soc-danger-main)',
  cancelled: 'var(--soc-text-disabled)',
  blocked: 'var(--soc-warning-main)',
  unknown: 'var(--soc-text-muted)',
};

export type EvidenceKindAccent =
  | 'observed'
  | 'correlated'
  | 'inferred'
  | 'unknown'
  | 'verified'
  | 'conflicted';

export function evidenceAccent(evidence: InvestigationEvidence): EvidenceKindAccent {
  if (evidence.type === 'INFERENCE') return 'inferred';
  if (evidence.type === 'HYPOTHESIS') return 'correlated';
  if (evidence.type === 'CONCLUSION') return 'verified';
  if (evidence.confidence >= 0.85) return 'verified';
  if (evidence.relationships.some((rel) => rel.type === 'WEAKENS')) return 'conflicted';
  if (evidence.relationships.length > 0) return 'correlated';
  return 'observed';
}

export function evidenceAccentVar(kind: EvidenceKindAccent): string {
  switch (kind) {
    case 'observed':
      return 'var(--soc-inv-observed)';
    case 'correlated':
      return 'var(--soc-inv-correlated)';
    case 'inferred':
      return 'var(--soc-inv-inferred)';
    case 'verified':
      return 'var(--soc-inv-verified)';
    case 'conflicted':
      return 'var(--soc-inv-conflicted)';
    default:
      return 'var(--soc-inv-unknown)';
  }
}

export function hypothesisAccent(hyp: InvestigationHypothesis): string {
  switch (hyp.status) {
    case 'PROMOTED':
    case 'SUPPORTED':
      return 'var(--soc-inv-verified)';
    case 'REJECTED':
    case 'WEAKENED':
      return 'var(--soc-inv-conflicted)';
    case 'OPEN':
    default:
      return 'var(--soc-inv-inferred)';
  }
}

export function formatRelative(timestamp: number, now: number = Date.now()): string {
  const delta = Math.max(0, now - timestamp);
  const sec = Math.floor(delta / 1000);
  if (sec < 5) return 'just now';
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

export function formatClock(timestamp: number): string {
  const d = new Date(timestamp);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
