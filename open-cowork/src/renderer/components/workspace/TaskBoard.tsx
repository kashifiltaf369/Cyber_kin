import { useMemo, useState } from 'react';
import {
  ListChecks,
  Pause,
  Play,
  X,
  ArrowUp,
  ArrowDown,
  Edit3,
} from 'lucide-react';
import type { Investigation, InvestigationTask } from '../../../shared/cyber/investigation-types';
import type {
  InvestigationPlan,
  PlannedInvestigationTask,
  InvestigationAgentRole,
} from '../../../main/investigation/parallel-investigation-engine';
import { WorkspacePanel } from './WorkspacePanel';
import {
  STATUS_LABEL,
  getRoleDescriptor,
  statusFromTask,
  type WorkerStatus,
} from './role-meta';

export interface TaskBoardProps {
  investigation: Investigation;
  plan: InvestigationPlan | null;
  tasksById: Map<string, InvestigationTask>;
  onPauseTask: (taskId: string) => void;
  onResumeTask: (taskId: string) => void;
  onCancelTask: (taskId: string) => void;
  onReprioritizeTask: (taskId: string, priority: number) => void;
  onRedirectTask: (taskId: string) => void;
}

type ColumnKey = 'queued' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled';

function toColumnKey(status: WorkerStatus): ColumnKey {
  if (status === 'unknown' || status === 'blocked') return 'queued';
  return status as ColumnKey;
}

const COLUMNS: Array<{ key: ColumnKey; label: string; accent: string; muted: string }> = [
  { key: 'running', label: 'Active', accent: 'var(--soc-accent-primary)', muted: 'var(--soc-accent-primary-muted)' },
  { key: 'queued', label: 'Queued', accent: 'var(--soc-text-muted)', muted: 'var(--soc-surface-elevated)' },
  { key: 'paused', label: 'Paused', accent: 'var(--soc-warning-main)', muted: 'var(--soc-warning-muted)' },
  { key: 'completed', label: 'Complete', accent: 'var(--soc-success-main)', muted: 'var(--soc-success-muted)' },
  { key: 'failed', label: 'Failed', accent: 'var(--soc-danger-main)', muted: 'var(--soc-danger-muted)' },
  { key: 'cancelled', label: 'Cancelled', accent: 'var(--soc-text-disabled)', muted: 'var(--soc-surface-elevated)' },
];

export function TaskBoard({
  investigation,
  plan,
  tasksById,
  onPauseTask,
  onResumeTask,
  onCancelTask,
  onReprioritizeTask,
  onRedirectTask,
}: TaskBoardProps) {
  const [showCompleted, setShowCompleted] = useState(true);

  const columns = useMemo(() => {
    const planned = plan?.tasks ?? [];
    const itemsByColumn = new Map<ColumnKey, Array<{ planned: PlannedInvestigationTask | null; runtime: InvestigationTask | undefined; status: ReturnType<typeof statusFromTask> }>>();

    for (const c of COLUMNS) itemsByColumn.set(c.key, []);

    const considered = new Set<string>();

    for (const p of planned) {
      const runtime = tasksById.get(p.id);
      const status = toColumnKey(statusFromTask(runtime));
      itemsByColumn.get(status)!.push({ planned: p, runtime, status });
      considered.add(p.id);
    }

    for (const runtime of investigation.aiTasks) {
      const pid = (runtime as InvestigationTask & { plannedTaskId?: string }).plannedTaskId;
      if (pid && considered.has(pid)) continue;
      const status = toColumnKey(statusFromTask(runtime));
      itemsByColumn.get(status)!.push({ planned: null, runtime, status });
    }
    return itemsByColumn;
  }, [plan, tasksById, investigation.aiTasks]);

  return (
    <WorkspacePanel
      title="Task board"
      subtitle={
        plan
          ? `${plan.tasks.length} planned · ${investigation.aiTasks.filter((t) => t.status === 'COMPLETED').length} done`
          : 'Plan pending'
      }
      icon={<ListChecks className="w-3.5 h-3.5" />}
      actions={
        <button
          onClick={() => setShowCompleted((s) => !s)}
          className="text-[10px] px-1.5 py-0.5 rounded uppercase tracking-wider font-semibold"
          style={{
            background: 'var(--soc-surface-elevated)',
            color: showCompleted ? 'var(--soc-text-secondary)' : 'var(--soc-text-muted)',
            border: '1px solid var(--soc-border-default)',
          }}
        >
          {showCompleted ? 'Hide done' : 'Show done'}
        </button>
      }
      density="compact"
      className="h-full"
      bodyClassName="p-0"
    >
      <div
        className="grid h-full"
        style={{
          gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
          gridTemplateRows: 'repeat(2, minmax(0, 1fr))',
          gap: 1,
          background: 'var(--soc-border-subtle)',
        }}
      >
        {COLUMNS.filter((c) => showCompleted || (c.key !== 'completed' && c.key !== 'cancelled')).map(
          (col) => {
            const items = columns.get(col.key) ?? [];
            return (
              <div
                key={col.key}
                className="flex flex-col min-h-0 overflow-hidden"
                style={{ background: 'var(--soc-bg-primary)' }}
              >
                <div
                  className="flex items-center justify-between px-2.5 py-1.5 border-b"
                  style={{ borderColor: 'var(--soc-border-subtle)' }}
                >
                  <div className="flex items-center gap-1.5">
                    <span
                      className="w-1.5 h-1.5 rounded-full"
                      style={{ background: col.accent }}
                    />
                    <span
                      className="text-[10.5px] font-semibold uppercase tracking-wider"
                      style={{ color: col.accent }}
                    >
                      {col.label}
                    </span>
                  </div>
                  <span
                    className="text-[10px] font-semibold px-1.5 py-0.5 rounded"
                    style={{ background: col.muted, color: col.accent }}
                  >
                    {items.length}
                  </span>
                </div>
                <div className="flex-1 min-h-0 overflow-y-auto p-1.5 space-y-1.5">
                  {items.length === 0 && (
                    <div
                      className="text-[10.5px] py-3 text-center"
                      style={{ color: 'var(--soc-text-disabled)' }}
                    >
                      Empty
                    </div>
                  )}
                  {items.map(({ planned, runtime, status }) => (
                    <TaskCard
                      key={planned?.id ?? runtime?.id ?? status}
                      planned={planned}
                      runtime={runtime}
                      onPause={() => runtime && onPauseTask(runtime.id)}
                      onResume={() => runtime && onResumeTask(runtime.id)}
                      onCancel={() => runtime && onCancelTask(runtime.id)}
                      onBumpPriority={(delta) =>
                        runtime && onReprioritizeTask(runtime.id, (runtime.priority ?? 0) + delta)
                      }
                      onRedirect={() => runtime && onRedirectTask(runtime.id)}
                    />
                  ))}
                </div>
              </div>
            );
          }
        )}
      </div>
    </WorkspacePanel>
  );
}

interface TaskCardProps {
  planned: PlannedInvestigationTask | null;
  runtime: InvestigationTask | undefined;
  onPause: () => void;
  onResume: () => void;
  onCancel: () => void;
  onBumpPriority: (delta: number) => void;
  onRedirect: () => void;
}

function TaskCard({
  planned,
  runtime,
  onPause,
  onResume,
  onCancel,
  onBumpPriority,
  onRedirect,
}: TaskCardProps) {
  const role: InvestigationAgentRole =
    planned?.role ?? (runtime?.owner as InvestigationAgentRole) ?? 'Research Investigator';
  const desc = getRoleDescriptor(role);
  const Icon = desc.icon;
  const status = statusFromTask(runtime);
  const isRunning = status === 'running';
  const isPaused = status === 'paused';
  const isDone = status === 'completed';
  const isCancelled = status === 'cancelled' || status === 'failed';
  const interactive = !isDone && !isCancelled;

  return (
    <div
      className="rounded-lg p-2 group"
      style={{
        background: 'var(--soc-surface-card)',
        border: '1px solid var(--soc-border-subtle)',
        borderLeft: `3px solid ${desc.accent}`,
      }}
    >
      <div className="flex items-start gap-1.5">
        <div
          className="flex items-center justify-center w-6 h-6 rounded shrink-0 mt-0.5"
          style={{ background: desc.accentMuted, color: desc.accent }}
        >
          <Icon className="w-3 h-3" />
        </div>
        <div className="min-w-0 flex-1">
          <div
            className="text-[11.5px] font-semibold leading-snug line-clamp-2"
            style={{ color: 'var(--soc-text-primary)' }}
            title={planned?.title ?? runtime?.title}
          >
            {planned?.title ?? runtime?.title ?? 'Task'}
          </div>
          <div
            className="text-[10px] mt-0.5 truncate"
            style={{ color: 'var(--soc-text-muted)' }}
          >
            {desc.shortLabel} · {STATUS_LABEL[status]}
          </div>
        </div>
      </div>

      {interactive && (
        <div className="flex items-center gap-0.5 mt-1.5 opacity-60 group-hover:opacity-100 transition-opacity">
          {isRunning && (
            <IconBtn title="Pause" onClick={onPause}>
              <Pause className="w-3 h-3" />
            </IconBtn>
          )}
          {isPaused && (
            <IconBtn title="Resume" onClick={onResume}>
              <Play className="w-3 h-3" />
            </IconBtn>
          )}
          <IconBtn title="Higher priority" onClick={() => onBumpPriority(1)}>
            <ArrowUp className="w-3 h-3" />
          </IconBtn>
          <IconBtn title="Lower priority" onClick={() => onBumpPriority(-1)}>
            <ArrowDown className="w-3 h-3" />
          </IconBtn>
          <IconBtn title="Redirect" onClick={onRedirect}>
            <Edit3 className="w-3 h-3" />
          </IconBtn>
          <div className="flex-1" />
          <IconBtn title="Cancel" onClick={onCancel} danger>
            <X className="w-3 h-3" />
          </IconBtn>
        </div>
      )}
    </div>
  );
}

function IconBtn({
  children,
  onClick,
  title,
  danger,
}: {
  children: React.ReactNode;
  onClick: () => void;
  title: string;
  danger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      title={title}
      className="flex items-center justify-center w-5 h-5 rounded transition-colors"
      style={{
        color: danger ? 'var(--soc-danger-main)' : 'var(--soc-text-muted)',
        background: 'transparent',
      }}
      onMouseEnter={(e) => {
        (e.currentTarget as HTMLElement).style.background = danger
          ? 'var(--soc-danger-muted)'
          : 'var(--soc-surface-elevated)';
        (e.currentTarget as HTMLElement).style.color = danger
          ? 'var(--soc-danger-main)'
          : 'var(--soc-text-primary)';
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLElement).style.background = 'transparent';
        (e.currentTarget as HTMLElement).style.color = danger
          ? 'var(--soc-danger-main)'
          : 'var(--soc-text-muted)';
      }}
    >
      {children}
    </button>
  );
}
