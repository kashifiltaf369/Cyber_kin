import { useMemo } from 'react';
import {
  Clock,
  Plus,
  CheckCircle2,
  Play,
  Pause,
  X,
  AlertTriangle,
  Beaker,
  GitBranch,
  FileText,
  ShieldAlert,
  Eye,
  Sparkles,
  Flag,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import type {
  Investigation,
  InvestigationEvent,
  InvestigationEventType,
  OperationalRationale,
} from '../../../shared/cyber/investigation-types';
import { isOperationalRationale } from '../../../shared/cyber/investigation-types';
import { WorkspacePanel } from './WorkspacePanel';
import { formatClock, formatRelative } from './role-meta';

export interface TimelineProps {
  investigation: Investigation;
}

const EVENT_ICON: Record<string, { icon: LucideIcon; color: string; muted: string }> = {
  INVESTIGATION_CREATED: { icon: Plus, color: 'var(--soc-info-main)', muted: 'var(--soc-info-muted)' },
  INVESTIGATION_OPENED: { icon: Eye, color: 'var(--soc-text-muted)', muted: 'var(--soc-surface-elevated)' },
  INVESTIGATION_RESUMED: { icon: Play, color: 'var(--soc-accent-primary)', muted: 'var(--soc-accent-primary-muted)' },
  INVESTIGATION_ARCHIVED: { icon: Flag, color: 'var(--soc-text-disabled)', muted: 'var(--soc-surface-elevated)' },
  INVESTIGATION_STATUS_CHANGED: { icon: GitBranch, color: 'var(--soc-info-main)', muted: 'var(--soc-info-muted)' },
  PLAN_CREATED: { icon: Sparkles, color: 'var(--soc-ai-primary)', muted: 'var(--soc-ai-background)' },
  TASK_CREATED: { icon: Plus, color: 'var(--soc-text-muted)', muted: 'var(--soc-surface-elevated)' },
  TASK_STARTED: { icon: Play, color: 'var(--soc-accent-primary)', muted: 'var(--soc-accent-primary-muted)' },
  TASK_COMPLETED: { icon: CheckCircle2, color: 'var(--soc-success-main)', muted: 'var(--soc-success-muted)' },
  TASK_UPDATED: { icon: FileText, color: 'var(--soc-text-muted)', muted: 'var(--soc-surface-elevated)' },
  TASK_PAUSED: { icon: Pause, color: 'var(--soc-warning-main)', muted: 'var(--soc-warning-muted)' },
  TASK_RESUMED: { icon: Play, color: 'var(--soc-accent-primary)', muted: 'var(--soc-accent-primary-muted)' },
  TASK_REPRIORITIZED: { icon: GitBranch, color: 'var(--soc-warning-main)', muted: 'var(--soc-warning-muted)' },
  TASK_IGNORED: { icon: X, color: 'var(--soc-text-disabled)', muted: 'var(--soc-surface-elevated)' },
  EVIDENCE_ADDED: { icon: Beaker, color: 'var(--soc-inv-verified)', muted: 'var(--soc-success-muted)' },
  EVIDENCE_LINKED: { icon: GitBranch, color: 'var(--soc-inv-correlated)', muted: 'var(--soc-info-muted)' },
  EVIDENCE_ANNOTATED: { icon: FileText, color: 'var(--soc-text-secondary)', muted: 'var(--soc-surface-elevated)' },
  GRAPH_RELATIONSHIP_ADDED: { icon: GitBranch, color: 'var(--soc-inv-correlated)', muted: 'var(--soc-info-muted)' },
  REPLAN_RECOMMENDED: { icon: AlertTriangle, color: 'var(--soc-warning-main)', muted: 'var(--soc-warning-muted)' },
  HYPOTHESIS_CREATED: { icon: Beaker, color: 'var(--soc-inv-inferred)', muted: 'var(--soc-warning-muted)' },
  HYPOTHESIS_UPDATED: { icon: Beaker, color: 'var(--soc-inv-inferred)', muted: 'var(--soc-warning-muted)' },
  HUMAN_INPUT_ADDED: { icon: FileText, color: 'var(--soc-text-secondary)', muted: 'var(--soc-surface-elevated)' },
  HUMAN_CONTEXT_ADDED: { icon: FileText, color: 'var(--soc-text-secondary)', muted: 'var(--soc-surface-elevated)' },
  CONSTRAINT_ADDED: { icon: ShieldAlert, color: 'var(--soc-danger-main)', muted: 'var(--soc-danger-muted)' },
  PRIORITY_ADDED: { icon: Flag, color: 'var(--soc-accent-primary)', muted: 'var(--soc-accent-primary-muted)' },
  NOTE_ADDED: { icon: FileText, color: 'var(--soc-text-muted)', muted: 'var(--soc-surface-elevated)' },
  AGENT_REDIRECTED: { icon: GitBranch, color: 'var(--soc-info-main)', muted: 'var(--soc-info-muted)' },
  CONCLUSION_UPDATED: { icon: Sparkles, color: 'var(--soc-success-main)', muted: 'var(--soc-success-muted)' },
  OPEN_QUESTION_ADDED: { icon: AlertTriangle, color: 'var(--soc-warning-main)', muted: 'var(--soc-warning-muted)' },
  DECISION_ADDED: { icon: CheckCircle2, color: 'var(--soc-success-main)', muted: 'var(--soc-success-muted)' },
  ENTITY_ADDED: { icon: GitBranch, color: 'var(--soc-inv-observed)', muted: 'var(--soc-info-muted)' },
  CYBER_ACTION_AUDITED: { icon: ShieldAlert, color: 'var(--soc-warning-main)', muted: 'var(--soc-warning-muted)' },
  OPERATIONAL_UPDATE: { icon: Sparkles, color: 'var(--soc-ai-primary)', muted: 'var(--soc-ai-background)' },
};

function lookup(type: string) {
  return (
    EVENT_ICON[type] ?? {
      icon: FileText,
      color: 'var(--soc-text-muted)',
      muted: 'var(--soc-surface-elevated)',
    }
  );
}

export function Timeline({ investigation }: TimelineProps) {
  const events: InvestigationEvent[] = useMemo(() => {
    const fromActivity = investigation.activity ?? [];
    const fromTimeline = investigation.timeline ?? [];
    const merged = new Map<string, InvestigationEvent>();
    for (const e of fromActivity) merged.set(e.id, e);
    for (const e of fromTimeline) merged.set(e.id, { ...merged.get(e.id), ...e } as InvestigationEvent);
    return Array.from(merged.values()).sort((a, b) => b.createdAt - a.createdAt);
  }, [investigation.activity, investigation.timeline]);

  return (
    <WorkspacePanel
      title="Timeline"
      subtitle={events.length > 0 ? `${events.length} events` : 'No events yet'}
      icon={<Clock className="w-3.5 h-3.5" />}
      density="compact"
      className="h-full"
    >
      {events.length === 0 ? (
        <div
          className="text-[12px] py-6 text-center"
          style={{ color: 'var(--soc-text-muted)' }}
        >
          Events from the AI team and your actions will appear here in chronological order.
        </div>
      ) : (
        <div className="relative">
          <div
            className="absolute top-0 bottom-0"
            style={{
              left: 9,
              width: 1,
              background: 'var(--soc-border-subtle)',
            }}
          />
          <ul className="space-y-2.5">
            {events.map((e) => {
              const meta = lookup(e.type);
              const Icon = meta.icon;
              const rationale = extractRationale(e.data);
              return (
                <li key={e.id} className="flex items-start gap-2.5 relative">
                  <div
                    className="flex items-center justify-center w-5 h-5 rounded-full shrink-0 z-10"
                    style={{
                      background: meta.muted,
                      border: '2px solid var(--soc-bg-primary)',
                      color: meta.color,
                    }}
                  >
                    <Icon className="w-2.5 h-2.5" />
                  </div>
                  <div className="min-w-0 flex-1 -mt-0.5">
                    <div className="flex items-center gap-1.5">
                      <span
                        className="text-[11px] font-semibold"
                        style={{ color: 'var(--soc-text-primary)' }}
                      >
                        {labelFor(e)}
                      </span>
                      <span
                        className="text-[10px] ml-auto font-mono shrink-0"
                        style={{ color: 'var(--soc-text-muted)' }}
                        title={formatClock(e.createdAt)}
                      >
                        {formatRelative(e.createdAt)}
                      </span>
                    </div>
                    {e.summary && (
                      <p
                        className="text-[11.5px] mt-0.5 leading-snug"
                        style={{ color: 'var(--soc-text-secondary)' }}
                      >
                        {e.summary}
                      </p>
                    )}
                    {rationale && <RationaleCard rationale={rationale} />}
                    <div className="text-[10px] mt-0.5" style={{ color: 'var(--soc-text-muted)' }}>
                      {e.actor} · {e.type.replace(/_/g, ' ').toLowerCase()}
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </WorkspacePanel>
  );
}

function labelFor(e: InvestigationEvent): string {
  const t = e.type as InvestigationEventType;
  const map: Partial<Record<InvestigationEventType, string>> = {
    INVESTIGATION_CREATED: 'Investigation created',
    INVESTIGATION_OPENED: 'Investigation opened',
    INVESTIGATION_RESUMED: 'Investigation resumed',
    INVESTIGATION_ARCHIVED: 'Investigation archived',
    INVESTIGATION_STATUS_CHANGED: 'Status changed',
    PLAN_CREATED: 'Plan created',
    TASK_CREATED: 'Task created',
    TASK_STARTED: 'Task started',
    TASK_COMPLETED: 'Task completed',
    TASK_UPDATED: 'Task updated',
    TASK_PAUSED: 'Task paused',
    TASK_RESUMED: 'Task resumed',
    TASK_REPRIORITIZED: 'Task reprioritized',
    TASK_IGNORED: 'Task ignored',
    EVIDENCE_ADDED: 'Evidence added',
    EVIDENCE_LINKED: 'Evidence linked',
    EVIDENCE_ANNOTATED: 'Evidence annotated',
    GRAPH_RELATIONSHIP_ADDED: 'Graph relationship added',
    REPLAN_RECOMMENDED: 'Replan recommended',
    HYPOTHESIS_CREATED: 'Hypothesis created',
    HYPOTHESIS_UPDATED: 'Hypothesis updated',
    HUMAN_INPUT_ADDED: 'Human input',
    HUMAN_CONTEXT_ADDED: 'Context added',
    CONSTRAINT_ADDED: 'Constraint added',
    PRIORITY_ADDED: 'Priority added',
    NOTE_ADDED: 'Note added',
    AGENT_REDIRECTED: 'Agent redirected',
    CONCLUSION_UPDATED: 'Conclusion updated',
    OPEN_QUESTION_ADDED: 'Open question added',
    DECISION_ADDED: 'Decision added',
    ENTITY_ADDED: 'Entity added',
    CYBER_ACTION_AUDITED: 'Cyber action audited',
    OPERATIONAL_UPDATE: 'Operational update',
  };
  return map[t] ?? (e.summary || 'Event');
}

function extractRationale(data: InvestigationEvent['data']): OperationalRationale | null {
  if (!data) return null;
  const candidate = data.operationalUpdate ?? data.rationale;
  return isOperationalRationale(candidate) ? candidate : null;
}

function RationaleCard({ rationale }: { rationale: OperationalRationale }) {
  const fields: Array<{ key: keyof OperationalRationale; label: string }> = [
    { key: 'what', label: 'WHAT' },
    { key: 'why', label: 'WHY' },
    { key: 'expectedValue', label: 'EXPECTED VALUE' },
  ];
  return (
    <div
      className="mt-1 rounded-md p-2 space-y-1"
      style={{
        background: 'var(--soc-surface-elevated)',
        border: '1px solid var(--soc-border-subtle)',
      }}
    >
      {fields.map((field) => {
        const value = rationale[field.key];
        if (typeof value !== 'string' || value.length === 0) return null;
        return (
          <div key={field.key} className="text-[11px] leading-snug">
            <span
              className="font-semibold mr-1.5"
              style={{ color: 'var(--soc-text-muted)' }}
            >
              {field.label}:
            </span>
            <span style={{ color: 'var(--soc-text-secondary)' }}>{value}</span>
          </div>
        );
      })}
      {rationale.result && (
        <div className="text-[11px] leading-snug">
          <span
            className="font-semibold mr-1.5"
            style={{ color: 'var(--soc-text-muted)' }}
          >
            RESULT:
          </span>
          <span style={{ color: 'var(--soc-text-secondary)' }}>{rationale.result}</span>
        </div>
      )}
      {rationale.next && (
        <div className="text-[11px] leading-snug">
          <span
            className="font-semibold mr-1.5"
            style={{ color: 'var(--soc-text-muted)' }}
          >
            NEXT:
          </span>
          <span style={{ color: 'var(--soc-text-secondary)' }}>{rationale.next}</span>
        </div>
      )}
    </div>
  );
}
