import { Swords, AlertTriangle } from 'lucide-react';
import type { Investigation, InvestigationHypothesis } from '../../../shared/cyber/investigation-types';
import { WorkspacePanel } from './WorkspacePanel';

export interface ChallengerFindingsPanelProps {
  investigation: Investigation;
}

export function ChallengerFindingsPanel({ investigation }: ChallengerFindingsPanelProps) {
  const weakened = investigation.hypotheses.filter(
    (h) => h.status === 'WEAKENED' || h.status === 'REJECTED'
  );
  const conflicted = investigation.evidence.filter(
    (ev) => ev.relationships.some((r) => r.type === 'WEAKENS')
  );
  const openUnresolved = investigation.hypotheses.filter(
    (h: InvestigationHypothesis) =>
      h.status === 'OPEN' && (h.unresolvedQuestions?.length ?? 0) > 0
  );
  const replanRec = investigation.activity
    .slice()
    .reverse()
    .find((e) => e.type === 'REPLAN_RECOMMENDED');

  const findings: Array<{ id: string; title: string; detail: string; tone: 'warn' | 'danger' | 'info' }> = [];

  for (const h of weakened) {
    findings.push({
      id: `h-${h.id}`,
      title: `Hypothesis ${h.status.toLowerCase()}: ${h.title}`,
      detail: `${h.contradictingEvidenceIds.length} contradicting evidence item(s).`,
      tone: h.status === 'REJECTED' ? 'danger' : 'warn',
    });
  }
  for (const ev of conflicted.slice(0, 5)) {
    findings.push({
      id: `e-${ev.id}`,
      title: `Evidence under challenge: ${ev.title}`,
      detail: 'Linked to a WEAKENS relationship. Re-examine the source.',
      tone: 'warn',
    });
  }
  for (const h of openUnresolved) {
    findings.push({
      id: `q-${h.id}`,
      title: `Unresolved inside: ${h.title}`,
      detail: (h.unresolvedQuestions ?? []).slice(0, 2).join(' · '),
      tone: 'info',
    });
  }
  if (replanRec) {
    findings.push({
      id: 'replan',
      title: 'Replan recommended by AI',
      detail: replanRec.summary,
      tone: 'warn',
    });
  }

  return (
    <WorkspacePanel
      title="Challenger findings"
      subtitle={
        findings.length === 0
          ? 'No active challenges'
          : `${findings.length} item${findings.length === 1 ? '' : 's'} to review`
      }
      icon={<Swords className="w-3.5 h-3.5" />}
      density="compact"
      className="h-full"
    >
      {findings.length === 0 ? (
        <div
          className="text-[12px] py-4 text-center"
          style={{ color: 'var(--soc-text-muted)' }}
        >
          The Challenger agent watches the team. Findings surface when hypotheses weaken or
          evidence is challenged.
        </div>
      ) : (
        <ul className="space-y-1.5">
          {findings.map((f) => {
            const color =
              f.tone === 'danger'
                ? 'var(--soc-danger-main)'
                : f.tone === 'warn'
                  ? 'var(--soc-warning-main)'
                  : 'var(--soc-info-main)';
            const muted =
              f.tone === 'danger'
                ? 'var(--soc-danger-muted)'
                : f.tone === 'warn'
                  ? 'var(--soc-warning-muted)'
                  : 'var(--soc-info-muted)';
            return (
              <li
                key={f.id}
                className="rounded-lg p-2.5"
                style={{
                  background: 'var(--soc-surface-card)',
                  border: '1px solid var(--soc-border-subtle)',
                  borderLeft: `3px solid ${color}`,
                }}
              >
                <div className="flex items-start gap-2">
                  <div
                    className="flex items-center justify-center w-6 h-6 rounded shrink-0"
                    style={{ background: muted, color }}
                  >
                    <AlertTriangle className="w-3 h-3" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div
                      className="text-[12px] font-semibold leading-snug"
                      style={{ color: 'var(--soc-text-primary)' }}
                    >
                      {f.title}
                    </div>
                    <p
                      className="text-[11px] mt-0.5 leading-snug"
                      style={{ color: 'var(--soc-text-secondary)' }}
                    >
                      {f.detail}
                    </p>
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </WorkspacePanel>
  );
}
