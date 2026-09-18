import { useState, useEffect } from 'react';
import {
  X,
  Pause,
  Play,
  Edit3,
  ArrowUp,
  ArrowDown,
  MessageSquare,
} from 'lucide-react';
import type {
  Investigation,
  InvestigationTask,
  InvestigationEvidence,
  OperationalRationale,
} from '../../../shared/cyber/investigation-types';
import { isOperationalRationale } from '../../../shared/cyber/investigation-types';
import type {
  PlannedInvestigationTask,
  InvestigationAgentRole,
} from '../../../main/investigation/parallel-investigation-engine';
import {
  getRoleDescriptor,
  statusFromTask,
  STATUS_LABEL,
  STATUS_COLOR,
  formatRelative,
  evidenceAccent,
  evidenceAccentVar,
} from './role-meta';

export interface WorkerInspectorProps {
  investigation: Investigation;
  planned: PlannedInvestigationTask | null;
  runtime: InvestigationTask | undefined;
  onClose: () => void;
  onPause: (taskId: string) => void;
  onResume: (taskId: string) => void;
  onCancel: (taskId: string) => void;
  onRedirect: (taskId: string) => void;
  onReprioritize: (taskId: string, priority: number) => void;
}

const ROLES: InvestigationAgentRole[] = [
  'Endpoint Investigator',
  'Network Investigator',
  'Identity Investigator',
  'Threat Intelligence Investigator',
  'Historical Investigator',
  'Evidence Analyst',
  'Research Investigator',
  'Challenger',
];

export function WorkerInspector({
  investigation,
  planned,
  runtime,
  onClose,
  onPause,
  onResume,
  onCancel,
  onRedirect,
  onReprioritize,
}: WorkerInspectorProps) {
  const role: InvestigationAgentRole =
    planned?.role ?? (runtime?.owner as InvestigationAgentRole) ?? 'Research Investigator';
  const desc = getRoleDescriptor(role);
  const Icon = desc.icon;
  const status = statusFromTask(runtime);
  const statusColor = STATUS_COLOR[status];

  const [redirectOpen, setRedirectOpen] = useState(false);
  const [newRole, setNewRole] = useState<InvestigationAgentRole>(role);
  const [newDescription, setNewDescription] = useState(planned?.description ?? '');

  useEffect(() => {
    setNewRole(role);
    setNewDescription(planned?.description ?? '');
    setRedirectOpen(false);
  }, [planned?.id, runtime?.id]);

  const linkedEvidence: InvestigationEvidence[] = (investigation.evidence ?? []).filter((ev) => {
    if (planned && ev.supportingTaskId === planned.id) return true;
    if (runtime && ev.investigator === runtime.id) return true;
    if (ev.investigator === role) return true;
    return false;
  });

  const latestRationale = latestOperationalRationale(investigation, planned, runtime);

  return (
    <div
      className="absolute inset-0 z-30 flex justify-end"
      style={{ background: 'rgba(8, 10, 13, 0.55)' }}
      onClick={onClose}
    >
      <div
        className="h-full w-[420px] max-w-[90vw] flex flex-col border-l shadow-2xl"
        style={{
          background: 'var(--soc-bg-secondary)',
          borderColor: 'var(--soc-border-default)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div
          className="flex items-center gap-2 px-4 py-3 border-b"
          style={{
            background: 'linear-gradient(180deg, var(--soc-bg-tertiary) 0%, var(--soc-bg-secondary) 100%)',
            borderColor: 'var(--soc-border-subtle)',
          }}
        >
          <div
            className="flex items-center justify-center w-8 h-8 rounded-lg"
            style={{ background: desc.accentMuted, color: desc.accent }}
          >
            <Icon className="w-4 h-4" />
          </div>
          <div className="min-w-0 flex-1">
            <div
              className="text-[10px] font-semibold uppercase tracking-[0.08em]"
              style={{ color: 'var(--soc-text-muted)' }}
            >
              Worker inspector
            </div>
            <div
              className="text-[14px] font-semibold truncate"
              style={{ color: 'var(--soc-text-primary)' }}
            >
              {desc.shortLabel}
            </div>
          </div>
          <button
            onClick={onClose}
            className="flex items-center justify-center w-7 h-7 rounded-md"
            style={{ color: 'var(--soc-text-muted)' }}
            title="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex-1 min-h-0 overflow-y-auto p-4 space-y-3">
          <div
            className="rounded-lg p-3 space-y-1.5"
            style={{
              background: 'var(--soc-surface-card)',
              border: '1px solid var(--soc-border-subtle)',
            }}
          >
            <div className="flex items-center gap-1.5">
              <span
                className="text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded"
                style={{ background: 'var(--soc-bg-tertiary)', color: statusColor }}
              >
                {STATUS_LABEL[status]}
              </span>
              {runtime?.updatedAt && (
                <span className="text-[10px]" style={{ color: 'var(--soc-text-muted)' }}>
                  updated {formatRelative(runtime.updatedAt)}
                </span>
              )}
            </div>
            <div
              className="text-[13px] font-semibold leading-snug"
              style={{ color: 'var(--soc-text-primary)' }}
            >
              {planned?.title ?? runtime?.title ?? 'Worker task'}
            </div>
            {(planned?.description ?? runtime?.description) && (
              <p
                className="text-[12px] leading-relaxed"
                style={{ color: 'var(--soc-text-secondary)' }}
              >
                {planned?.description ?? runtime?.description}
              </p>
            )}
            {planned && (
              <div className="flex flex-wrap gap-1.5 pt-1">
                {planned.dependsOn?.length > 0 && (
                  <span
                    className="text-[10px] px-1.5 py-0.5 rounded"
                    style={{
                      background: 'var(--soc-surface-elevated)',
                      color: 'var(--soc-text-muted)',
                    }}
                  >
                    depends on {planned.dependsOn.length} task(s)
                  </span>
                )}
                <span
                  className="text-[10px] px-1.5 py-0.5 rounded"
                  style={{
                    background: 'var(--soc-surface-elevated)',
                    color: 'var(--soc-text-muted)',
                  }}
                >
                  kind: {planned.kind}
                </span>
                <span
                  className="text-[10px] px-1.5 py-0.5 rounded"
                  style={{
                    background: 'var(--soc-surface-elevated)',
                    color: 'var(--soc-text-muted)',
                  }}
                >
                  merge: {planned.mergeStrategy.replace(/_/g, ' ')}
                </span>
              </div>
            )}
          </div>

          {latestRationale && <RationalePanel rationale={latestRationale.rationale} updatedAt={latestRationale.updatedAt} />}

          <div className="flex items-center gap-1.5 flex-wrap">
            {runtime && status === 'running' && (
              <ActionBtn onClick={() => onPause(runtime.id)} icon={<Pause className="w-3 h-3" />} label="Pause" tone="warn" />
            )}
            {runtime && status === 'paused' && (
              <ActionBtn onClick={() => onResume(runtime.id)} icon={<Play className="w-3 h-3" />} label="Resume" tone="ok" />
            )}
            {runtime && status !== 'completed' && status !== 'cancelled' && (
              <>
                <ActionBtn
                  onClick={() => onReprioritize(runtime.id, (runtime.priority ?? 0) + 1)}
                  icon={<ArrowUp className="w-3 h-3" />}
                  label="Higher"
                />
                <ActionBtn
                  onClick={() => onReprioritize(runtime.id, (runtime.priority ?? 0) - 1)}
                  icon={<ArrowDown className="w-3 h-3" />}
                  label="Lower"
                />
                <ActionBtn
                  onClick={() => setRedirectOpen((s) => !s)}
                  icon={<Edit3 className="w-3 h-3" />}
                  label="Redirect"
                />
                <ActionBtn
                  onClick={() => onCancel(runtime.id)}
                  icon={<X className="w-3 h-3" />}
                  label="Cancel"
                  tone="danger"
                />
              </>
            )}
          </div>

          {redirectOpen && runtime && (
            <div
              className="rounded-lg p-3 space-y-2"
              style={{
                background: 'var(--soc-surface-card)',
                border: '1px solid var(--soc-border-default)',
              }}
            >
              <div
                className="text-[10px] font-semibold uppercase tracking-wider"
                style={{ color: 'var(--soc-text-muted)' }}
              >
                Redirect worker
              </div>
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value as InvestigationAgentRole)}
                className="w-full rounded-md px-2 py-1 text-[12px] outline-none"
                style={{
                  background: 'var(--soc-bg-primary)',
                  border: '1px solid var(--soc-border-default)',
                  color: 'var(--soc-text-primary)',
                }}
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
              <textarea
                value={newDescription}
                onChange={(e) => setNewDescription(e.target.value)}
                rows={3}
                placeholder="New objective for this worker…"
                className="w-full rounded-md px-2 py-1.5 text-[12px] outline-none resize-none"
                style={{
                  background: 'var(--soc-bg-primary)',
                  border: '1px solid var(--soc-border-default)',
                  color: 'var(--soc-text-primary)',
                }}
              />
              <div className="flex items-center justify-end gap-1.5">
                <button
                  onClick={() => setRedirectOpen(false)}
                  className="px-2 py-1 rounded-md text-[11px] font-semibold"
                  style={{
                    background: 'var(--soc-bg-tertiary)',
                    color: 'var(--soc-text-secondary)',
                    border: '1px solid var(--soc-border-default)',
                  }}
                >
                  Cancel
                </button>
                <button
                  onClick={() => {
                    onRedirect(runtime.id);
                    setRedirectOpen(false);
                  }}
                  className="px-2 py-1 rounded-md text-[11px] font-semibold"
                  style={{ background: 'var(--soc-accent-primary)', color: '#00131F' }}
                >
                  Apply redirect
                </button>
              </div>
            </div>
          )}

          <div
            className="rounded-lg overflow-hidden"
            style={{
              background: 'var(--soc-surface-card)',
              border: '1px solid var(--soc-border-subtle)',
            }}
          >
            <div
              className="px-3 py-2 border-b flex items-center gap-1.5"
              style={{ borderColor: 'var(--soc-border-subtle)' }}
            >
              <MessageSquare className="w-3 h-3" style={{ color: 'var(--soc-text-muted)' }} />
              <span
                className="text-[10.5px] font-semibold uppercase tracking-wider"
                style={{ color: 'var(--soc-text-secondary)' }}
              >
                Linked evidence ({linkedEvidence.length})
              </span>
            </div>
            {linkedEvidence.length === 0 ? (
              <div
                className="text-[12px] py-4 text-center"
                style={{ color: 'var(--soc-text-muted)' }}
              >
                No evidence linked yet.
              </div>
            ) : (
              <ul className="divide-y" style={{ borderColor: 'var(--soc-border-subtle)' }}>
                {linkedEvidence.slice(0, 12).map((ev) => {
                  const accent = evidenceAccentVar(evidenceAccent(ev));
                  return (
                    <li key={ev.id} className="px-3 py-2 flex items-start gap-2">
                      <div
                        className="w-1 self-stretch rounded-full shrink-0"
                        style={{ background: accent }}
                      />
                      <div className="min-w-0 flex-1">
                        <div
                          className="text-[12px] font-semibold leading-snug truncate"
                          style={{ color: 'var(--soc-text-primary)' }}
                        >
                          {ev.title}
                        </div>
                        <div
                          className="text-[10px]"
                          style={{ color: 'var(--soc-text-muted)' }}
                        >
                          {ev.kind} · {formatRelative(ev.collectedAt)} ·{' '}
                          {Math.round(ev.confidence * 100)}% confidence
                        </div>
                        {ev.summary && (
                          <p
                            className="text-[11px] mt-0.5 line-clamp-2 leading-snug"
                            style={{ color: 'var(--soc-text-secondary)' }}
                          >
                            {ev.summary}
                          </p>
                        )}
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function ActionBtn({
  onClick,
  icon,
  label,
  tone,
}: {
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
  tone?: 'warn' | 'ok' | 'danger';
}) {
  const color =
    tone === 'warn'
      ? 'var(--soc-warning-main)'
      : tone === 'danger'
        ? 'var(--soc-danger-main)'
        : tone === 'ok'
          ? 'var(--soc-success-main)'
          : 'var(--soc-text-secondary)';
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-semibold"
      style={{
        background: 'var(--soc-surface-elevated)',
        color,
        border: `1px solid var(--soc-border-default)`,
      }}
    >
      {icon}
      {label}
    </button>
  );
}

function latestOperationalRationale(
  investigation: Investigation,
  planned: PlannedInvestigationTask | null,
  runtime: InvestigationTask | undefined
): { rationale: OperationalRationale; updatedAt: number } | null {
  const events = investigation.activity ?? [];
  const plannedId = planned?.id;
  const runtimeId = runtime?.id;
  const role = planned?.role ?? (runtime?.owner as InvestigationAgentRole | undefined);
  for (let i = events.length - 1; i >= 0; i -= 1) {
    const event = events[i];
    if (event.type !== 'OPERATIONAL_UPDATE') continue;
    const data = event.data || {};
    const taskIdMatch = plannedId && (data.taskId === runtimeId || data.plannedTaskId === plannedId);
    const roleMatch = role && data.role === role;
    if (!taskIdMatch && !roleMatch) continue;
    const candidate = data.operationalUpdate ?? data.rationale;
    if (isOperationalRationale(candidate)) {
      return { rationale: candidate, updatedAt: event.createdAt };
    }
  }
  return null;
}

function RationalePanel({
  rationale,
  updatedAt,
}: {
  rationale: OperationalRationale;
  updatedAt: number;
}) {
  const fields: Array<{ key: keyof OperationalRationale; label: string }> = [
    { key: 'what', label: 'WHAT' },
    { key: 'why', label: 'WHY' },
    { key: 'expectedValue', label: 'EXPECTED VALUE' },
  ];
  return (
    <div
      className="rounded-lg p-3 space-y-1.5"
      style={{
        background: 'var(--soc-surface-card)',
        border: '1px solid var(--soc-border-subtle)',
      }}
    >
      <div className="flex items-center justify-between gap-2">
        <div
          className="text-[10px] font-semibold uppercase tracking-wider"
          style={{ color: 'var(--soc-text-muted)' }}
        >
          Operational update
        </div>
        <div className="text-[10px]" style={{ color: 'var(--soc-text-muted)' }}>
          {formatRelative(updatedAt)}
        </div>
      </div>
      {fields.map((field) => {
        const value = rationale[field.key];
        if (typeof value !== 'string' || value.length === 0) return null;
        return (
          <div key={field.key} className="text-[11.5px] leading-snug">
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
        <div className="text-[11.5px] leading-snug">
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
        <div className="text-[11.5px] leading-snug">
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
