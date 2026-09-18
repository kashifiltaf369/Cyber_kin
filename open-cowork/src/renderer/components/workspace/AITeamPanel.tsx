import { useMemo } from 'react';
import { Users, Eye } from 'lucide-react';
import type { Investigation, InvestigationTask } from '../../../shared/cyber/investigation-types';
import type {
  InvestigationPlan,
  PlannedInvestigationTask,
  InvestigationAgentRole,
} from '../../../main/investigation/parallel-investigation-engine';
import { WorkspacePanel } from './WorkspacePanel';
import {
  STATUS_COLOR,
  STATUS_LABEL,
  formatRelative,
  getRoleDescriptor,
  statusFromTask,
} from './role-meta';

export interface AITeamPanelProps {
  investigation: Investigation;
  plan: InvestigationPlan | null;
  onInspectTask: (planned: PlannedInvestigationTask, task: InvestigationTask | undefined) => void;
}

export function AITeamPanel({ investigation, plan, onInspectTask }: AITeamPanelProps) {
  const plannedTasks = plan?.tasks ?? [];

  const workerRows = useMemo(() => {
    if (plannedTasks.length === 0) {
      const fallback: { planned: PlannedInvestigationTask | null; runtime: InvestigationTask | undefined }[] =
        investigation.aiTasks.map((t) => ({ planned: null, runtime: t }));
      return fallback;
    }

    const byRole = new Map<string, PlannedInvestigationTask>();
    const coveredPlannedIds = new Set<string>();
    for (const t of plannedTasks) {
      if (!byRole.has(t.role)) byRole.set(t.role, t);
      coveredPlannedIds.add(t.id);
    }

    const rows: { planned: PlannedInvestigationTask | null; runtime: InvestigationTask | undefined }[] = [];
    for (const planned of byRole.values()) {
      const runtime = investigation.aiTasks.find(
        (t) => (t as InvestigationTask & { plannedTaskId?: string }).plannedTaskId === planned.id
      );
      rows.push({ planned, runtime });
    }

    for (const runtime of investigation.aiTasks) {
      const plannedId = (runtime as InvestigationTask & { plannedTaskId?: string }).plannedTaskId;
      if (plannedId && coveredPlannedIds.has(plannedId)) continue;
      rows.push({ planned: null, runtime });
    }
    return rows;
  }, [plannedTasks, investigation.aiTasks]);

  const summary = useMemo(() => {
    const statuses = workerRows.map((r) => statusFromTask(r.runtime));
    const investigating = statuses.filter((s) => s === 'running').length;
    const complete = statuses.filter((s) => s === 'completed').length;
    const queued = statuses.filter((s) => s === 'queued' || s === 'blocked' || s === 'unknown').length;
    return { investigating, complete, queued, total: statuses.length };
  }, [workerRows]);

  return (
    <WorkspacePanel
      title="AI Team"
      subtitle={`${summary.investigating} investigating · ${summary.complete} complete · ${summary.queued} waiting`}
      icon={<Users className="w-3.5 h-3.5" />}
      density="compact"
      className="h-full"
      bodyClassName="p-0"
    >
      <div className="flex flex-col">
        {workerRows.length === 0 && (
          <div
            className="px-3.5 py-6 text-center text-[12px]"
            style={{ color: 'var(--soc-text-muted)' }}
          >
            No plan yet. Workers will appear here once a plan is generated.
          </div>
        )}
        {workerRows.map(({ planned, runtime }, idx) => {
          const role: InvestigationAgentRole =
            (planned?.role as InvestigationAgentRole) ??
            (runtime?.owner as InvestigationAgentRole) ??
            'Research Investigator';
          const desc = getRoleDescriptor(role);
          const Icon = desc.icon;
          const status = statusFromTask(runtime);
          const color = STATUS_COLOR[status];
          const label = STATUS_LABEL[status];
          const findings = planned
            ? countRoleEvidence(investigation, planned.id, role)
            : 0;
          const isLast = idx === workerRows.length - 1;

          return (
            <button
              key={planned?.id ?? runtime?.id ?? `${role}-${idx}`}
              type="button"
              onClick={() => onInspectTask(planned as PlannedInvestigationTask, runtime)}
              className="group flex items-center gap-3 px-3.5 py-2.5 text-left transition-colors w-full"
              style={{
                borderBottom: isLast ? 'none' : '1px solid var(--soc-border-subtle)',
                background: 'transparent',
              }}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLElement).style.background = 'var(--soc-surface-card-hover)';
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLElement).style.background = 'transparent';
              }}
            >
              <div
                className="flex items-center justify-center w-9 h-9 rounded-lg shrink-0"
                style={{ background: desc.accentMuted, color: desc.accent }}
              >
                <Icon className="w-4 h-4" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5">
                  <span
                    className="text-[13px] font-semibold truncate"
                    style={{ color: 'var(--soc-text-primary)' }}
                  >
                    {desc.shortLabel}
                  </span>
                  <span
                    className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded"
                    style={{
                      color: color,
                      background: statusBg(status),
                    }}
                  >
                    {label}
                  </span>
                </div>
                <div
                  className="text-[11px] truncate"
                  style={{ color: 'var(--soc-text-muted)' }}
                  title={planned?.title ?? runtime?.title}
                >
                  {planned?.title ?? runtime?.title ?? role}
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {findings > 0 && (
                  <span
                    className="text-[10px] font-medium px-1.5 py-0.5 rounded"
                    style={{
                      color: 'var(--soc-inv-verified)',
                      background: 'var(--soc-success-muted)',
                    }}
                  >
                    {findings} findings
                  </span>
                )}
                {runtime?.updatedAt && (
                  <span
                    className="text-[10px]"
                    style={{ color: 'var(--soc-text-muted)' }}
                  >
                    {formatRelative(runtime.updatedAt)}
                  </span>
                )}
                <span
                  className="opacity-0 group-hover:opacity-100 transition-opacity"
                  style={{ color: 'var(--soc-text-muted)' }}
                >
                  <Eye className="w-3.5 h-3.5" />
                </span>
              </div>
            </button>
          );
        })}
      </div>
    </WorkspacePanel>
  );
}

function statusBg(s: ReturnType<typeof statusFromTask>): string {
  switch (s) {
    case 'running':
      return 'var(--soc-accent-primary-muted)';
    case 'completed':
      return 'var(--soc-success-muted)';
    case 'paused':
    case 'blocked':
      return 'var(--soc-warning-muted)';
    case 'failed':
    case 'cancelled':
      return 'var(--soc-danger-muted)';
    default:
      return 'var(--soc-surface-elevated)';
  }
}

function countRoleEvidence(
  investigation: Investigation,
  plannedTaskId: string,
  role: string
): number {
  let n = 0;
  for (const ev of investigation.evidence) {
    if (ev.supportingTaskId === plannedTaskId) {
      n += 1;
      continue;
    }
    if (ev.investigator === role) n += 1;
  }
  return n;
}
