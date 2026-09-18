import { useState } from 'react';
import { Sparkles, ChevronDown, ChevronRight, CheckCircle2 } from 'lucide-react';
import type { Investigation, InvestigationConclusion } from '../../../shared/cyber/investigation-types';
import { WorkspacePanel } from './WorkspacePanel';
import { formatRelative } from './role-meta';

export interface AISynthesisPanelProps {
  investigation: Investigation;
}

export function AISynthesisPanel({ investigation }: AISynthesisPanelProps) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const conclusions: InvestigationConclusion[] = investigation.conclusions ?? [];
  const promotedHypotheses = investigation.hypotheses.filter((h) => h.status === 'PROMOTED');

  return (
    <WorkspacePanel
      title="AI synthesis"
      subtitle={
        conclusions.length === 0
          ? 'Awaiting sufficient evidence'
          : `${conclusions.length} conclusion${conclusions.length === 1 ? '' : 's'}`
      }
      icon={<Sparkles className="w-3.5 h-3.5" />}
      density="compact"
      className="h-full"
    >
      <div className="flex flex-col gap-2.5">
        {conclusions.length === 0 && promotedHypotheses.length === 0 && (
          <div
            className="text-[12px] py-4 text-center"
            style={{ color: 'var(--soc-text-muted)' }}
          >
            The team will synthesize a candidate conclusion as confidence grows. Your job is to challenge and approve.
          </div>
        )}

        {conclusions.length > 0 && (
          <ul className="space-y-1.5">
            {[...conclusions]
              .sort((a, b) => b.updatedAt - a.updatedAt)
              .map((c) => {
                const isOpen = expanded[c.id] ?? true;
                return (
                  <li
                    key={c.id}
                    className="rounded-lg overflow-hidden"
                    style={{
                      background: 'var(--soc-surface-card)',
                      border: '1px solid var(--soc-border-subtle)',
                      borderLeft: '3px solid var(--soc-ai-primary)',
                    }}
                  >
                    <button
                      onClick={() => setExpanded((m) => ({ ...m, [c.id]: !(m[c.id] ?? true) }))}
                      className="w-full text-left p-2.5 flex items-start gap-2"
                    >
                      <Sparkles
                        className="w-3.5 h-3.5 mt-0.5 shrink-0"
                        style={{ color: 'var(--soc-ai-primary)' }}
                      />
                      <div className="min-w-0 flex-1">
                        <div
                          className="text-[12.5px] font-semibold leading-snug"
                          style={{ color: 'var(--soc-text-primary)' }}
                        >
                          {c.summary}
                        </div>
                        <div
                          className="text-[10px] mt-0.5"
                          style={{ color: 'var(--soc-text-muted)' }}
                        >
                          {Math.round(c.confidence * 100)}% confidence · updated{' '}
                          {formatRelative(c.updatedAt)}
                        </div>
                      </div>
                      <div style={{ color: 'var(--soc-text-muted)' }}>
                        {isOpen ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                      </div>
                    </button>
                    {isOpen && (
                      <div
                        className="px-3 py-2.5 border-t space-y-2"
                        style={{ borderColor: 'var(--soc-border-subtle)' }}
                      >
                        {c.rationale && (
                          <p
                            className="text-[11.5px] leading-relaxed"
                            style={{ color: 'var(--soc-text-secondary)' }}
                          >
                            {c.rationale}
                          </p>
                        )}
                        {c.derivedFromHypothesisIds.length > 0 && (
                          <div
                            className="text-[10px] flex items-center gap-1"
                            style={{ color: 'var(--soc-text-muted)' }}
                          >
                            <CheckCircle2 className="w-3 h-3" />
                            Supported by {c.derivedFromHypothesisIds.length} hypothesis
                            {c.derivedFromHypothesisIds.length === 1 ? '' : 'es'} ·{' '}
                            {c.derivedFromEvidenceIds.length} evidence
                          </div>
                        )}
                      </div>
                    )}
                  </li>
                );
              })}
          </ul>
        )}

        {promotedHypotheses.length > 0 && (
          <div
            className="rounded-lg p-2.5 space-y-1.5"
            style={{
              background: 'var(--soc-success-muted)',
              border: '1px solid var(--soc-success-main)',
              borderStyle: 'dashed',
            }}
          >
            <div
              className="text-[10px] font-semibold uppercase tracking-wider"
              style={{ color: 'var(--soc-success-main)' }}
            >
              Promoted hypotheses
            </div>
            {promotedHypotheses.map((h) => (
              <div
                key={h.id}
                className="text-[12px] leading-snug"
                style={{ color: 'var(--soc-text-primary)' }}
              >
                {h.title}
              </div>
            ))}
          </div>
        )}
      </div>
    </WorkspacePanel>
  );
}
