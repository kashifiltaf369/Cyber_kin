import { useMemo } from 'react';
import {
  ShieldHalf,
  Pause,
  Play,
  Archive,
  RefreshCw,
  Zap,
  GitBranch,
  Clock,
  CheckCircle2,
  AlertTriangle,
  CircleDashed,
} from 'lucide-react';
import type { Investigation } from '../../../shared/cyber/investigation-types';
import { useActiveInvestigationPlan, useActiveInvestigationReplan } from '../../store/selectors';
import { formatRelative } from './role-meta';

export interface InvestigationHeaderProps {
  investigation: Investigation;
  onPauseAll?: () => void;
  onResumeAll?: () => void;
  onReplan?: () => void;
  onArchive?: () => void;
  onExecute?: () => void;
}

const STATUS_PRESENTATION: Record<
  Investigation['status'],
  { label: string; color: string; dot: string }
> = {
  CREATED: { label: 'Created', color: 'var(--soc-text-muted)', dot: 'var(--soc-text-muted)' },
  PLANNING: { label: 'Planning', color: 'var(--soc-info-main)', dot: 'var(--soc-info-main)' },
  INVESTIGATING: {
    label: 'Investigating',
    color: 'var(--soc-accent-primary)',
    dot: 'var(--soc-accent-primary)',
  },
  WAITING_FOR_HUMAN: {
    label: 'Awaiting human',
    color: 'var(--soc-warning-main)',
    dot: 'var(--soc-warning-main)',
  },
  REPLANNING: { label: 'Replanning', color: 'var(--soc-inv-inferred)', dot: 'var(--soc-inv-inferred)' },
  CONCLUDED: { label: 'Concluded', color: 'var(--soc-success-main)', dot: 'var(--soc-success-main)' },
  ARCHIVED: { label: 'Archived', color: 'var(--soc-text-disabled)', dot: 'var(--soc-text-disabled)' },
};

export function InvestigationHeader({
  investigation,
  onPauseAll,
  onResumeAll,
  onReplan,
  onArchive,
  onExecute,
}: InvestigationHeaderProps) {
  const plan = useActiveInvestigationPlan();
  const replan = useActiveInvestigationReplan();

  const status = STATUS_PRESENTATION[investigation.status] ?? STATUS_PRESENTATION.CREATED;

  const stats = useMemo(() => {
    const tasks = plan?.tasks ?? [];
    const completed = tasks.filter((t) => t.kind === 'investigative').length;
    return {
      planTasks: tasks.length,
      evidenceCount: investigation.evidence.length,
      hypothesisCount: investigation.hypotheses.length,
      openQuestions: investigation.openQuestions.length,
      confidence: Math.round((investigation.confidence ?? 0) * 100),
      completed,
    };
  }, [plan, investigation]);

  const isLive = investigation.status === 'INVESTIGATING';
  const isPaused = investigation.status === 'WAITING_FOR_HUMAN' || investigation.status === 'REPLANNING';
  const isConcluded = investigation.status === 'CONCLUDED' || investigation.status === 'ARCHIVED';

  return (
    <div
      className="flex flex-col gap-3 px-5 py-4 border-b"
      style={{
        background: 'linear-gradient(180deg, var(--soc-bg-secondary) 0%, var(--soc-bg-primary) 100%)',
        borderColor: 'var(--soc-border-subtle)',
      }}
    >
      <div className="flex items-start gap-4">
        <div
          className="flex items-center justify-center w-10 h-10 rounded-xl shrink-0"
          style={{
            background: 'linear-gradient(135deg, var(--soc-ai-background), var(--soc-bg-tertiary))',
            border: '1px solid var(--soc-ai-border)',
            color: 'var(--soc-ai-primary)',
          }}
        >
          <ShieldHalf className="w-5 h-5" />
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span
              className="text-[10px] font-semibold tracking-[0.16em] uppercase"
              style={{ color: 'var(--soc-text-muted)' }}
            >
              Investigation
            </span>
            <span
              className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold"
              style={{ background: 'var(--soc-bg-tertiary)', color: status.color }}
            >
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{
                  background: status.dot,
                  boxShadow: isLive ? `0 0 6px ${status.dot}` : 'none',
                  animation: isLive ? 'soc-pulse 1.6s ease-in-out infinite' : undefined,
                }}
              />
              {status.label}
            </span>
            {replan && (
              <span
                className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium"
                style={{
                  background: 'var(--soc-warning-muted)',
                  color: 'var(--soc-warning-main)',
                }}
                title="A replan was recommended"
              >
                <GitBranch className="w-3 h-3" /> Replan pending
              </span>
            )}
          </div>
          <h1
            className="text-[19px] font-semibold leading-tight tracking-[-0.01em] truncate"
            style={{ color: 'var(--soc-text-primary)' }}
          >
            {investigation.title || 'Untitled investigation'}
          </h1>
          <p
            className="mt-1 text-[12.5px] leading-relaxed line-clamp-2"
            style={{ color: 'var(--soc-text-secondary)' }}
          >
            {investigation.objective}
          </p>
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          {!isConcluded && !isLive && (
            <button
              onClick={onExecute}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold transition-colors"
              style={{
                background: 'var(--soc-accent-primary)',
                color: '#00131F',
              }}
            >
              <Zap className="w-3.5 h-3.5" />
              Start investigation
            </button>
          )}
          {isLive && (
            <button
              onClick={onPauseAll}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold transition-colors"
              style={{
                background: 'var(--soc-warning-muted)',
                color: 'var(--soc-warning-main)',
                border: '1px solid var(--soc-warning-main)',
              }}
            >
              <Pause className="w-3.5 h-3.5" /> Pause
            </button>
          )}
          {isPaused && (
            <button
              onClick={onResumeAll}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold transition-colors"
              style={{
                background: 'var(--soc-success-muted)',
                color: 'var(--soc-success-main)',
                border: '1px solid var(--soc-success-main)',
              }}
            >
              <Play className="w-3.5 h-3.5" /> Resume
            </button>
          )}
          <button
            onClick={onReplan}
            disabled={isConcluded}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[12px] font-medium transition-colors disabled:opacity-40"
            style={{
              background: 'var(--soc-surface-elevated)',
              color: 'var(--soc-text-secondary)',
              border: '1px solid var(--soc-border-default)',
            }}
            title="Replan investigation"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={onArchive}
            disabled={isConcluded}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[12px] font-medium transition-colors disabled:opacity-40"
            style={{
              background: 'var(--soc-surface-elevated)',
              color: 'var(--soc-text-secondary)',
              border: '1px solid var(--soc-border-default)',
            }}
            title="Archive"
          >
            <Archive className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <StatChip
          icon={<CircleDashed className="w-3 h-3" />}
          label="Plan"
          value={stats.planTasks > 0 ? `${stats.planTasks} tasks` : 'Not planned'}
        />
        <StatChip
          icon={<CheckCircle2 className="w-3 h-3" />}
          label="Evidence"
          value={String(stats.evidenceCount)}
        />
        <StatChip
          icon={<AlertTriangle className="w-3 h-3" />}
          label="Hypotheses"
          value={String(stats.hypothesisCount)}
        />
        <StatChip
          icon={<AlertTriangle className="w-3 h-3" />}
          label="Open Qs"
          value={String(stats.openQuestions)}
        />
        <StatChip
          icon={<Zap className="w-3 h-3" />}
          label="Confidence"
          value={`${stats.confidence}%`}
          accent={
            stats.confidence >= 70
              ? 'var(--soc-success-main)'
              : stats.confidence >= 40
                ? 'var(--soc-warning-main)'
                : 'var(--soc-text-muted)'
          }
        />
        <StatChip
          icon={<Clock className="w-3 h-3" />}
          label="Updated"
          value={formatRelative(investigation.updatedAt)}
        />
      </div>
    </div>
  );
}

function StatChip({
  icon,
  label,
  value,
  accent,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  accent?: string;
}) {
  return (
    <div
      className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-[11px]"
      style={{
        background: 'var(--soc-surface-elevated)',
        border: '1px solid var(--soc-border-subtle)',
        color: 'var(--soc-text-secondary)',
      }}
    >
      <span style={{ color: accent ?? 'var(--soc-text-muted)' }}>{icon}</span>
      <span style={{ color: 'var(--soc-text-muted)' }}>{label}</span>
      <span className="font-semibold" style={{ color: accent ?? 'var(--soc-text-primary)' }}>
        {value}
      </span>
    </div>
  );
}
