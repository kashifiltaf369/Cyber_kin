import { useEffect, useRef } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Check,
  X,
  Monitor,
  Loader2,
  MessageSquare,
  Flag,
  CircleHelp,
} from 'lucide-react';
import type { DemoControllerState } from '../../../shared/cyber/demo-types';
import { useIPC } from '../../hooks/useIPC';

/**
 * Demo Mode control surface — the single UI consumer of the deterministic
 * scenario controller's state. Renders, depending on phase:
 *  - KIN narration strip (what the team is doing right now)
 *  - the blocking approval card (phase: awaiting-approval — scenario is
 *    physically stopped until APPROVE / DECLINE)
 *  - the computer-use action stream (phase: computer-use)
 *  - the honest denied state (phase: denied)
 *  - the conclusion card (phase: complete)
 */
export function DemoControlCard({ demoState }: { demoState: DemoControllerState }) {
  const { invoke, isElectron } = useIPC();
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [demoState.messages.length, demoState.computerActions.length]);

  if (!isElectron || demoState.phase === 'idle') return null;

  const latestMessage = demoState.messages[demoState.messages.length - 1];

  const answer = async (approve: boolean) => {
    if (!demoState.approval) return;
    await invoke<{ success: boolean }>(
      approve
        ? ({ type: 'demo.approve', payload: { stepId: demoState.approval.stepId } } as const)
        : ({ type: 'demo.deny', payload: { stepId: demoState.approval.stepId } } as const)
    );
  };

  return (
    <div className="flex flex-col gap-2" data-testid="demo-control-card">
      {/* KIN narration strip */}
      {latestMessage && demoState.phase !== 'denied' && (
        <div
          className="flex items-start gap-2 rounded-xl px-3 py-2"
          style={{ background: 'var(--soc-ai-background)', border: '1px solid var(--soc-ai-border)' }}
        >
          <MessageSquare className="w-3.5 h-3.5 shrink-0 mt-0.5" style={{ color: 'var(--soc-ai-primary)' }} />
          <div className="min-w-0">
            <div
              className="text-[10px] font-semibold uppercase tracking-[0.14em]"
              style={{ color: 'var(--soc-ai-primary)' }}
            >
              KIN team
            </div>
            <div className="text-[12.5px] leading-snug" style={{ color: 'var(--soc-text-primary)' }}>
              {latestMessage.text}
            </div>
          </div>
        </div>
      )}

      {/* Correlation chain strip (deterministic controller state) */}
      {demoState.correlationChain.length > 0 && demoState.phase !== 'denied' && (
        <div
          className="flex items-center gap-1.5 flex-wrap rounded-xl px-3 py-2"
          style={{ background: 'var(--soc-surface-card)', border: '1px solid var(--soc-border-subtle)' }}
          data-testid="demo-correlation-chain"
        >
          <span
            className="text-[10px] font-semibold uppercase tracking-[0.14em] mr-1"
            style={{ color: 'var(--soc-text-muted)' }}
          >
            Correlation chain
          </span>
          {demoState.correlationChain.map((node, index) => (
            <span key={node} className="inline-flex items-center gap-1.5">
              {index > 0 && (
                <span style={{ color: 'var(--soc-ai-primary)' }} className="text-[11px]">
                  →
                </span>
              )}
              <span
                className="px-1.5 py-0.5 rounded text-[11px] font-medium"
                style={{ background: 'var(--soc-ai-background)', color: 'var(--soc-ai-primary)', border: '1px solid var(--soc-ai-border)' }}
              >
                {node}
              </span>
            </span>
          ))}
        </div>
      )}

      {/* Blocking approval card */}
      {demoState.phase === 'awaiting-approval' && demoState.approval && demoState.approval.status === 'pending' && (
        <div
          data-testid="demo-approval-card"
          className="rounded-xl px-3.5 py-3 demo-approval-glow"
          style={{
            background: 'var(--soc-surface-card)',
            border: '1.5px solid var(--soc-warning-main)',
          }}
        >
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4" style={{ color: 'var(--soc-warning-main)' }} />
            <span className="text-[12px] font-bold uppercase tracking-wide" style={{ color: 'var(--soc-warning-main)' }}>
              Action blocked — approval required
            </span>
          </div>
          <div className="mt-2 text-[13px] font-semibold" style={{ color: 'var(--soc-text-primary)' }}>
            {demoState.approval.title}
          </div>
          <div className="text-[12px] mt-0.5" style={{ color: 'var(--soc-text-muted)' }}>
            Target: {demoState.approval.target} · Risk: {demoState.approval.risk} · {demoState.approval.purpose}
          </div>
          {demoState.nextStep && (
            <div className="text-[11.5px] mt-1" style={{ color: 'var(--soc-text-muted)' }}>
              Expected value: <span style={{ color: 'var(--soc-success-main)' }}>{demoState.nextStep.expectedValue}</span> — {demoState.nextStep.why}
            </div>
          )}
          <div className="flex items-center gap-2 mt-2.5">
            <button
              data-testid="demo-approve"
              onClick={() => answer(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold hover:opacity-90"
              style={{ background: 'var(--soc-success-main)', color: '#00281C' }}
            >
              <Check className="w-3.5 h-3.5" /> Approve
            </button>
            <button
              data-testid="demo-decline"
              onClick={() => answer(false)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold hover:opacity-90"
              style={{ background: 'transparent', color: 'var(--soc-danger-main)', border: '1px solid var(--soc-danger-main)' }}
            >
              <X className="w-3.5 h-3.5" /> Decline
            </button>
            <span className="text-[11px] ml-1" style={{ color: 'var(--soc-text-muted)' }}>
              The scenario is paused until you decide.
            </span>
          </div>
        </div>
      )}

      {/* Computer-use action stream */}
      {demoState.computerActions.length > 0 && (
        <div
          className="rounded-xl px-3.5 py-3"
          style={{ background: 'var(--soc-surface-card)', border: '1px solid var(--soc-ai-border)' }}
          data-testid="demo-computer-use"
        >
          <div className="flex items-center gap-2">
            <Monitor className="w-4 h-4" style={{ color: 'var(--soc-ai-secondary)' }} />
            <span className="text-[12px] font-bold uppercase tracking-wide" style={{ color: 'var(--soc-ai-secondary)' }}>
              Computer use — approved actions (demo endpoint)
            </span>
          </div>
          <ul className="mt-2 space-y-1.5">
            {demoState.computerActions.map((action) => (
              <li key={action.id} className="flex items-start gap-2" data-testid={`demo-cu-${action.action}`}>
                {action.status === 'done' ? (
                  <Check className="w-3.5 h-3.5 shrink-0 mt-0.5" style={{ color: 'var(--soc-success-main)' }} />
                ) : (
                  <Loader2 className="w-3.5 h-3.5 shrink-0 mt-0.5 animate-spin" style={{ color: 'var(--soc-ai-secondary)' }} />
                )}
                <div className="min-w-0">
                  <span className="text-[12px] font-mono" style={{ color: 'var(--soc-text-primary)' }}>
                    {action.action}
                  </span>
                  <span className="text-[11.5px]" style={{ color: 'var(--soc-text-muted)' }}>
                    {' '}→ {action.target}
                  </span>
                  {action.observation && (
                    <div className="text-[11.5px]" style={{ color: 'var(--soc-text-secondary, var(--soc-text-primary))' }}>
                      {action.observation}
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Denied state — honest outcome */}
      {demoState.phase === 'denied' && (
        <div
          data-testid="demo-denied"
          className="rounded-xl px-3.5 py-3"
          style={{ background: 'var(--soc-surface-card)', border: '1px solid var(--soc-danger-main)' }}
        >
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4" style={{ color: 'var(--soc-danger-main)' }} />
            <span className="text-[12px] font-bold uppercase tracking-wide" style={{ color: 'var(--soc-danger-main)' }}>
              Action declined by human
            </span>
          </div>
          <div className="text-[12.5px] mt-1" style={{ color: 'var(--soc-text-primary)' }}>
            {latestMessage?.text}
          </div>
        </div>
      )}

      {/* Conclusion card */}
      {demoState.conclusion && (
        <div
          data-testid="demo-conclusion"
          className="rounded-xl px-3.5 py-3"
          style={{ background: 'var(--soc-surface-card)', border: '1.5px solid var(--soc-success-main)' }}
        >
          <div className="flex items-center gap-2">
            <Flag className="w-4 h-4" style={{ color: 'var(--soc-success-main)' }} />
            <span className="text-[12px] font-bold uppercase tracking-wide" style={{ color: 'var(--soc-success-main)' }}>
              Conclusion — confidence {demoState.conclusion.confidence} ({demoState.conclusion.confidencePercent}%)
            </span>
          </div>
          <div className="text-[13px] mt-1 leading-snug" style={{ color: 'var(--soc-text-primary)' }}>
            {demoState.conclusion.assessment}
          </div>
          <div className="flex flex-wrap gap-1.5 mt-2">
            {demoState.conclusion.supportingEvidenceTags.map((tag) => (
              <span
                key={tag}
                className="px-1.5 py-0.5 rounded text-[10.5px] font-semibold"
                style={{ background: 'var(--soc-success-muted)', color: 'var(--soc-success-main)' }}
              >
                {tag}
              </span>
            ))}
          </div>
          {demoState.conclusion.remainingUnknowns.length > 0 && (
            <div className="mt-2">
              <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide" style={{ color: 'var(--soc-warning-main)' }}>
                <CircleHelp className="w-3 h-3" /> Still unknown
              </div>
              <ul className="mt-1 space-y-0.5">
                {demoState.conclusion.remainingUnknowns.map((unknown) => (
                  <li key={unknown} className="text-[11.5px]" style={{ color: 'var(--soc-text-muted)' }}>
                    • {unknown}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div className="mt-2 text-[11.5px]" style={{ color: 'var(--soc-text-muted)' }}>
            Recommended next: {demoState.conclusion.recommendedNextSteps.join(' · ')}
          </div>
        </div>
      )}

      {/* Auto-scrolling narration history (compact, after approval started) */}
      {(demoState.phase === 'computer-use' || demoState.phase === 'complete' || demoState.phase === 'concluding') && (
        <div ref={scrollRef} className="max-h-24 overflow-y-auto rounded-xl px-3 py-2" style={{ background: 'var(--soc-surface-card)', border: '1px solid var(--soc-border-subtle)' }}>
          {demoState.messages.slice(-4).map((message) => (
            <div key={message.id} className="text-[11.5px] leading-snug py-0.5" style={{ color: 'var(--soc-text-muted)' }}>
              <ShieldCheck className="w-3 h-3 inline mr-1.5 -mt-0.5" style={{ color: 'var(--soc-ai-primary)' }} />
              {message.text}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
