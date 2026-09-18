import { useState, useRef, useEffect } from 'react';
import {
  Send,
  Pause,
  Play,
  GitBranch,
  Sparkles,
  FlaskConical,
  ShieldAlert,
  MessageSquareWarning,
} from 'lucide-react';
import type { Investigation } from '../../../shared/cyber/investigation-types';
import { useActiveInvestigationRecommendation } from '../../store/selectors';

export type CommandKind =
  | 'message'
  | 'pause_all'
  | 'resume_all'
  | 'replan'
  | 'add_hypothesis'
  | 'add_suspicion'
  | 'add_constraint'
  | 'note';

export interface HumanCommandBarProps {
  investigation: Investigation;
  onSendCommand: (kind: CommandKind, payload: string) => void;
  onApproveReplan?: () => void;
  onRejectReplan?: () => void;
}

export function HumanCommandBar({
  investigation,
  onSendCommand,
  onApproveReplan,
  onRejectReplan,
}: HumanCommandBarProps) {
  const recommendation = useActiveInvestigationRecommendation();
  const [text, setText] = useState('');
  const [kind, setKind] = useState<CommandKind>('message');
  const inputRef = useRef<HTMLTextAreaElement | null>(null);

  useEffect(() => {
    if (kind === 'add_hypothesis' || kind === 'add_suspicion' || kind === 'add_constraint' || kind === 'note') {
      inputRef.current?.focus();
    }
  }, [kind]);

  const isLive = investigation.status === 'INVESTIGATING';
  const isPaused = investigation.status === 'WAITING_FOR_HUMAN' || investigation.status === 'REPLANNING';

  const placeholder: Record<CommandKind, string> = {
    message: 'Send a directive to the AI team… (e.g. "focus on lateral movement from HR-VPN-04")',
    pause_all: '',
    resume_all: '',
    replan: 'Why should we replan? (optional)',
    add_hypothesis: 'State your hypothesis clearly…',
    add_suspicion: 'What looks suspicious?',
    add_constraint: 'Hard rule the team must respect…',
    note: 'Add a note for the team…',
  };

  const send = () => {
    const value = text.trim();
    if (kind === 'message' || kind === 'add_hypothesis' || kind === 'add_suspicion' || kind === 'add_constraint' || kind === 'note') {
      if (!value) return;
    }
    onSendCommand(kind, value);
    setText('');
  };

  return (
    <div
      className="border-t"
      style={{
        background: 'var(--soc-bg-secondary)',
        borderColor: 'var(--soc-border-subtle)',
      }}
    >
      {recommendation && onApproveReplan && onRejectReplan && (
        <div
          className="flex items-center gap-3 px-4 py-2 border-b"
          style={{
            background: 'var(--soc-warning-muted)',
            borderColor: 'var(--soc-warning-main)',
          }}
        >
          <GitBranch className="w-3.5 h-3.5" style={{ color: 'var(--soc-warning-main)' }} />
          <div className="min-w-0 flex-1">
            <div
              className="text-[11px] font-semibold uppercase tracking-wider"
              style={{ color: 'var(--soc-warning-main)' }}
            >
              Replan recommendation
            </div>
            <div
              className="text-[12px] truncate"
              style={{ color: 'var(--soc-text-primary)' }}
            >
              {recommendation.summary}
            </div>
          </div>
          <button
            onClick={onRejectReplan}
            className="px-2.5 py-1 rounded-md text-[11px] font-semibold"
            style={{
              background: 'var(--soc-bg-tertiary)',
              color: 'var(--soc-text-secondary)',
              border: '1px solid var(--soc-border-default)',
            }}
          >
            Reject
          </button>
          <button
            onClick={onApproveReplan}
            className="px-2.5 py-1 rounded-md text-[11px] font-semibold"
            style={{ background: 'var(--soc-success-main)', color: '#0B0F14' }}
          >
            Approve replan
          </button>
        </div>
      )}

      <div className="flex items-center gap-1.5 px-4 pt-2.5">
        <KindButton active={kind === 'message'} onClick={() => setKind('message')}>
          <MessageSquareWarning className="w-3 h-3" /> Message
        </KindButton>
        <KindButton active={kind === 'add_hypothesis'} onClick={() => setKind('add_hypothesis')}>
          <FlaskConical className="w-3 h-3" /> Hypothesis
        </KindButton>
        <KindButton active={kind === 'add_suspicion'} onClick={() => setKind('add_suspicion')}>
          <ShieldAlert className="w-3 h-3" /> Suspicion
        </KindButton>
        <KindButton active={kind === 'add_constraint'} onClick={() => setKind('add_constraint')}>
          <ShieldAlert className="w-3 h-3" /> Constraint
        </KindButton>
        <KindButton active={kind === 'note'} onClick={() => setKind('note')}>
          <Sparkles className="w-3 h-3" /> Note
        </KindButton>

        <div className="flex-1" />

        {isLive && (
          <button
            onClick={() => onSendCommand('pause_all', '')}
            className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-semibold"
            style={{
              background: 'var(--soc-warning-muted)',
              color: 'var(--soc-warning-main)',
              border: '1px solid var(--soc-warning-main)',
            }}
          >
            <Pause className="w-3 h-3" /> Pause all
          </button>
        )}
        {isPaused && (
          <button
            onClick={() => onSendCommand('resume_all', '')}
            className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-semibold"
            style={{
              background: 'var(--soc-success-muted)',
              color: 'var(--soc-success-main)',
              border: '1px solid var(--soc-success-main)',
            }}
          >
            <Play className="w-3 h-3" /> Resume all
          </button>
        )}
        <button
          onClick={() => onSendCommand('replan', text)}
          className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-semibold"
          style={{
            background: 'var(--soc-surface-elevated)',
            color: 'var(--soc-text-secondary)',
            border: '1px solid var(--soc-border-default)',
          }}
        >
          <GitBranch className="w-3 h-3" /> Replan
        </button>
      </div>

      <div className="flex items-end gap-2 px-4 pt-2 pb-3">
        <textarea
          ref={inputRef}
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              send();
            }
          }}
          rows={2}
          placeholder={placeholder[kind]}
          className="flex-1 resize-none rounded-md px-3 py-2 text-[12.5px] outline-none"
          style={{
            background: 'var(--soc-bg-primary)',
            border: '1px solid var(--soc-border-default)',
            color: 'var(--soc-text-primary)',
          }}
        />
        <button
          onClick={send}
          disabled={!text.trim() && (kind === 'message' || kind === 'add_hypothesis' || kind === 'add_suspicion' || kind === 'add_constraint' || kind === 'note')}
          className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md text-[12px] font-semibold disabled:opacity-40"
          style={{ background: 'var(--soc-accent-primary)', color: '#00131F' }}
        >
          <Send className="w-3.5 h-3.5" />
          Send
        </button>
      </div>
    </div>
  );
}

function KindButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-semibold transition-colors"
      style={{
        background: active ? 'var(--soc-accent-primary-muted)' : 'transparent',
        color: active ? 'var(--soc-accent-primary)' : 'var(--soc-text-muted)',
        border: `1px solid ${active ? 'var(--soc-accent-primary)' : 'transparent'}`,
      }}
    >
      {children}
    </button>
  );
}
