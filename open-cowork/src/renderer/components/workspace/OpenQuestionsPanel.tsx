import { HelpCircle, Check } from 'lucide-react';
import type { Investigation } from '../../../shared/cyber/investigation-types';
import { WorkspacePanel } from './WorkspacePanel';

export interface OpenQuestionsPanelProps {
  investigation: Investigation;
  onResolveQuestion?: (index: number) => void;
}

export function OpenQuestionsPanel({ investigation, onResolveQuestion }: OpenQuestionsPanelProps) {
  const questions = investigation.openQuestions ?? [];

  return (
    <WorkspacePanel
      title="Open questions"
      subtitle={questions.length === 0 ? 'All clear' : `${questions.length} pending`}
      icon={<HelpCircle className="w-3.5 h-3.5" />}
      density="compact"
      className="h-full"
    >
      {questions.length === 0 ? (
        <div
          className="text-[12px] py-4 text-center"
          style={{ color: 'var(--soc-text-muted)' }}
        >
          No open questions. The team will raise them as gaps in evidence appear.
        </div>
      ) : (
        <ul className="space-y-1.5">
          {questions.map((q, i) => (
            <li
              key={`${q}-${i}`}
              className="flex items-start gap-2 rounded-lg p-2"
              style={{
                background: 'var(--soc-surface-card)',
                border: '1px solid var(--soc-border-subtle)',
                borderLeft: '3px solid var(--soc-warning-main)',
              }}
            >
              <HelpCircle
                className="w-3.5 h-3.5 shrink-0 mt-0.5"
                style={{ color: 'var(--soc-warning-main)' }}
              />
              <span
                className="text-[12px] leading-snug flex-1"
                style={{ color: 'var(--soc-text-primary)' }}
              >
                {q}
              </span>
              {onResolveQuestion && (
                <button
                  onClick={() => onResolveQuestion(i)}
                  className="flex items-center justify-center w-5 h-5 rounded shrink-0"
                  style={{
                    background: 'var(--soc-success-muted)',
                    color: 'var(--soc-success-main)',
                  }}
                  title="Mark resolved"
                >
                  <Check className="w-3 h-3" />
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </WorkspacePanel>
  );
}
