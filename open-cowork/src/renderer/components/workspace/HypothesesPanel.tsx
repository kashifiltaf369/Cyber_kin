import { useState } from 'react';
import { FlaskConical, Plus, ArrowUp, ArrowDown, Beaker } from 'lucide-react';
import type {
  Investigation,
  InvestigationHypothesis,
} from '../../../shared/cyber/investigation-types';
import { WorkspacePanel } from './WorkspacePanel';
import { formatRelative, hypothesisAccent } from './role-meta';

export interface HypothesesPanelProps {
  investigation: Investigation;
  onAddHypothesis: (title: string, statement: string) => void;
  onPromote: (id: string) => void;
  onReject: (id: string) => void;
}

const STATUS_LABEL: Record<InvestigationHypothesis['status'], string> = {
  OPEN: 'Open',
  SUPPORTED: 'Supported',
  WEAKENED: 'Weakened',
  REJECTED: 'Rejected',
  PROMOTED: 'Promoted',
};

export function HypothesesPanel({ investigation, onAddHypothesis, onPromote, onReject }: HypothesesPanelProps) {
  const [draftTitle, setDraftTitle] = useState('');
  const [draftStatement, setDraftStatement] = useState('');

  const submit = () => {
    if (!draftTitle.trim()) return;
    onAddHypothesis(draftTitle.trim(), draftStatement.trim() || draftTitle.trim());
    setDraftTitle('');
    setDraftStatement('');
  };

  return (
    <WorkspacePanel
      title="Hypotheses"
      subtitle={`${investigation.hypotheses.length} tracked`}
      icon={<FlaskConical className="w-3.5 h-3.5" />}
      density="compact"
      className="h-full"
    >
      <div className="flex flex-col gap-2">
        <div
          className="rounded-lg p-2 space-y-1.5"
          style={{
            background: 'var(--soc-bg-tertiary)',
            border: '1px solid var(--soc-border-subtle)',
          }}
        >
          <input
            value={draftTitle}
            onChange={(e) => setDraftTitle(e.target.value)}
            placeholder="Hypothesis title…"
            className="w-full bg-transparent text-[12px] font-semibold outline-none"
            style={{ color: 'var(--soc-text-primary)' }}
          />
          <textarea
            value={draftStatement}
            onChange={(e) => setDraftStatement(e.target.value)}
            placeholder="Statement of what you suspect is happening…"
            rows={2}
            className="w-full bg-transparent text-[11.5px] outline-none resize-none"
            style={{ color: 'var(--soc-text-secondary)' }}
          />
          <div className="flex justify-end">
            <button
              onClick={submit}
              disabled={!draftTitle.trim()}
              className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-semibold disabled:opacity-40"
              style={{ background: 'var(--soc-accent-primary)', color: '#00131F' }}
            >
              <Plus className="w-3 h-3" /> Add hypothesis
            </button>
          </div>
        </div>

        {investigation.hypotheses.length === 0 ? (
          <div
            className="text-[12px] py-4 text-center"
            style={{ color: 'var(--soc-text-muted)' }}
          >
            No hypotheses yet. The team will propose them as evidence comes in.
          </div>
        ) : (
          <ul className="space-y-1.5">
            {[...investigation.hypotheses]
              .sort((a, b) => b.updatedAt - a.updatedAt)
              .map((h) => {
                const accent = hypothesisAccent(h);
                return (
                  <li
                    key={h.id}
                    className="rounded-lg p-2.5"
                    style={{
                      background: 'var(--soc-surface-card)',
                      border: '1px solid var(--soc-border-subtle)',
                      borderLeft: `3px solid ${accent}`,
                    }}
                  >
                    <div className="flex items-start gap-2">
                      <div
                        className="flex items-center justify-center w-6 h-6 rounded shrink-0 mt-0.5"
                        style={{ background: 'var(--soc-bg-tertiary)', color: accent }}
                      >
                        <Beaker className="w-3 h-3" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-1.5">
                          <span
                            className="text-[12px] font-semibold leading-snug"
                            style={{ color: 'var(--soc-text-primary)' }}
                          >
                            {h.title}
                          </span>
                          <span
                            className="text-[9.5px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded"
                            style={{ background: 'var(--soc-surface-elevated)', color: accent }}
                          >
                            {STATUS_LABEL[h.status]}
                          </span>
                          <span
                            className="ml-auto text-[10px]"
                            style={{ color: 'var(--soc-text-muted)' }}
                            title={`Confidence ${Math.round(h.confidence * 100)}%`}
                          >
                            {Math.round(h.confidence * 100)}%
                          </span>
                        </div>
                        <p
                          className="text-[11.5px] mt-1 leading-snug"
                          style={{ color: 'var(--soc-text-secondary)' }}
                        >
                          {h.statement}
                        </p>
                        <div
                          className="flex items-center gap-2 mt-1.5 text-[10px]"
                          style={{ color: 'var(--soc-text-muted)' }}
                        >
                          <span>+{h.supportingEvidenceIds.length} support</span>
                          <span>−{h.contradictingEvidenceIds.length} weaken</span>
                          <span>· {h.createdBy}</span>
                          <span className="ml-auto">{formatRelative(h.updatedAt)}</span>
                        </div>
                        {h.status !== 'PROMOTED' && h.status !== 'REJECTED' && (
                          <div className="flex items-center gap-1 mt-1.5">
                            <button
                              onClick={() => onPromote(h.id)}
                              className="inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded"
                              style={{
                                background: 'var(--soc-success-muted)',
                                color: 'var(--soc-success-main)',
                              }}
                            >
                              <ArrowUp className="w-2.5 h-2.5" /> Promote
                            </button>
                            <button
                              onClick={() => onReject(h.id)}
                              className="inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded"
                              style={{
                                background: 'var(--soc-danger-muted)',
                                color: 'var(--soc-danger-main)',
                              }}
                            >
                              <ArrowDown className="w-2.5 h-2.5" /> Reject
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  </li>
                );
              })}
          </ul>
        )}
      </div>
    </WorkspacePanel>
  );
}
