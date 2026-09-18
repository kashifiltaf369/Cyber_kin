import { useCallback, useEffect, useMemo, useState } from 'react';
import { FileDown, Loader2, ScrollText, ShieldAlert } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { WorkspacePanel } from './WorkspacePanel';
import { formatRelative } from './role-meta';

const ORIGIN_BADGE: Record<string, { label: string; tone: 'observed' | 'human' | 'humanContext' | 'ai' | 'aiChallenger' | 'derived' }> = {
  observed_evidence: { label: 'OBSERVED EVIDENCE', tone: 'observed' },
  human_decision: { label: 'HUMAN DECISION', tone: 'human' },
  human_context: { label: 'HUMAN CONTEXT', tone: 'humanContext' },
  ai_assessment: { label: 'AI ASSESSMENT', tone: 'ai' },
  ai_challenger: { label: 'AI CHALLENGER', tone: 'aiChallenger' },
  derived_conclusion: { label: 'DERIVED CONCLUSION', tone: 'derived' },
};

type InvestigationReport = import('../../../main/investigation/investigation-report-service').InvestigationReport;
type ReportEvidenceRef = import('../../../main/investigation/investigation-report-service').ReportEvidenceRef;

export interface InvestigationReportPanelProps {
  investigationId: string;
}

export function InvestigationReportPanel({ investigationId }: InvestigationReportPanelProps) {
  const { t } = useTranslation();
  const [report, setReport] = useState<InvestigationReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [exportStatus, setExportStatus] = useState<{ kind: 'idle' | 'success' | 'error'; message?: string }>({ kind: 'idle' });

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    window.electronAPI.investigation
      .getReport(investigationId)
      .then((value) => {
        if (cancelled) return;
        setReport(value);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [investigationId]);

  const onExport = useCallback(async () => {
    setExportStatus({ kind: 'idle' });
    const result = await window.electronAPI.investigation.exportReport(investigationId);
    if (result.success) {
      setExportStatus({ kind: 'success', message: result.path });
    } else {
      setExportStatus({ kind: 'error', message: result.error });
    }
    setTimeout(() => setExportStatus({ kind: 'idle' }), 5000);
  }, [investigationId]);

  const evidenceById = useMemo(() => {
    const m = new Map<string, ReportEvidenceRef>();
    (report?.evidence || []).forEach((ref) => m.set(ref.evidenceId, ref));
    return m;
  }, [report]);

  return (
    <WorkspacePanel
      title={t('investigation.report.title', 'Investigation Report')}
      subtitle={
        loading
          ? t('investigation.report.loading', 'Loading…')
          : report
          ? `${Math.round(report.confidenceAssessment.overall * 100)}% · ${report.evidence.length} evidence · ${report.hypotheses.length} hypotheses`
          : t('investigation.report.empty', 'No report available')
      }
      icon={<ScrollText className="w-3.5 h-3.5" />}
      density="comfortable"
      actions={
        <button
          onClick={onExport}
          disabled={loading || !report}
          className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded border"
          style={{
            borderColor: 'var(--soc-border-subtle)',
            color: 'var(--soc-text-secondary)',
            background: 'var(--soc-surface-elevated)',
          }}
        >
          <FileDown className="w-3 h-3" />
          {t('investigation.report.export', 'Export Markdown')}
        </button>
      }
    >
      <div className="flex flex-col gap-3 text-[12px]">
        {loading && (
          <div className="flex items-center gap-2 text-[var(--soc-text-muted)]">
            <Loader2 className="w-3.5 h-3.5 animate-spin" /> {t('investigation.report.loading', 'Loading…')}
          </div>
        )}
        {error && (
          <div className="flex items-center gap-2 text-[var(--soc-text-danger)]">
            <ShieldAlert className="w-3.5 h-3.5" /> {error}
          </div>
        )}
        {exportStatus.kind === 'success' && exportStatus.message && (
          <div className="text-[var(--soc-text-success)]">Exported to {exportStatus.message}</div>
        )}
        {exportStatus.kind === 'error' && exportStatus.message && (
          <div className="text-[var(--soc-text-danger)]">{exportStatus.message}</div>
        )}

        {report && <ReportBody report={report} evidenceById={evidenceById} t={t} />}
      </div>
    </WorkspacePanel>
  );
}

function ReportBody({
  report,
  evidenceById,
  t,
}: {
  report: InvestigationReport;
  evidenceById: Map<string, ReportEvidenceRef>;
  t: (key: string, fallback: string) => string;
}) {
  return (
    <>
      <Section title={t('investigation.report.executive', 'Executive Summary')} origin={report.executiveSummary.origin}>
        <p className="leading-relaxed">{report.executiveSummary.text}</p>
        <p className="text-[11px] mt-1" style={{ color: 'var(--soc-text-muted)' }}>
          Confidence: {Math.round(report.executiveSummary.confidence * 100)}%
        </p>
      </Section>

      <Section title={t('investigation.report.objective', 'Investigation Objective')} origin="human_context">
        <p>{report.objective}</p>
      </Section>

      <Section title={t('investigation.report.humanContext', 'Human Analyst Context')} origin="human_context">
        {report.humanContext.priorities.length > 0 && (
          <SubList label="Priorities" items={report.humanContext.priorities} />
        )}
        {report.humanContext.constraints.length > 0 && (
          <SubList label="Constraints" items={report.humanContext.constraints} />
        )}
        {report.humanContext.suspicions.length > 0 && (
          <SubList label="Suspicions" items={report.humanContext.suspicions} />
        )}
        {report.humanContext.knownLegitimateBehavior.length > 0 && (
          <SubList label="Known Legitimate Behavior" items={report.humanContext.knownLegitimateBehavior} />
        )}
        {report.humanContext.knownAbnormalBehavior.length > 0 && (
          <SubList label="Known Abnormal Behavior" items={report.humanContext.knownAbnormalBehavior} />
        )}
        <p className="text-[11px]" style={{ color: 'var(--soc-text-muted)' }}>
          Risk tolerance: {report.humanContext.riskTolerance}
        </p>
        {report.humanContext.decisions.length > 0 && (
          <SubList
            label="Human Decisions"
            items={report.humanContext.decisions.map(
              (decision) => `${decision.summary}${decision.rationale ? ` — ${decision.rationale}` : ''}`
            )}
          />
        )}
      </Section>

      <Section title={t('investigation.report.timeline', 'Timeline')} origin="observed_evidence">
        {report.timeline.length === 0 ? (
          <Empty>{t('investigation.report.noTimeline', 'No timeline events recorded.')}</Empty>
        ) : (
          <ul className="space-y-1">
            {[...report.timeline]
              .sort((a, b) => a.occurredAt - b.occurredAt)
              .slice(0, 12)
              .map((entry) => (
                <li key={entry.id} className="text-[11.5px]">
                  <span className="text-[var(--soc-text-muted)]">{formatRelative(entry.occurredAt)}</span> · {entry.summary}
                </li>
              ))}
          </ul>
        )}
      </Section>

      <Section title={t('investigation.report.entities', 'Key Entities')} origin="observed_evidence">
        {report.keyEntities.length === 0 ? (
          <Empty>{t('investigation.report.noEntities', 'No entities recorded.')}</Empty>
        ) : (
          <ul className="space-y-0.5">
            {report.keyEntities.map(({ entity, linkedEvidenceCount }) => (
              <li key={entity.id} className="text-[11.5px]">
                <strong>{entity.name}</strong> <span className="text-[var(--soc-text-muted)]">({entity.type})</span>
                {linkedEvidenceCount > 0 && (
                  <span className="text-[var(--soc-text-muted)]"> · {linkedEvidenceCount} evidence</span>
                )}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={t('investigation.report.evidence', 'Evidence')} origin="observed_evidence">
        {report.evidence.length === 0 ? (
          <Empty>{t('investigation.report.noEvidence', 'No evidence has been collected.')}</Empty>
        ) : (
          <ul className="space-y-1.5">
            {[...report.evidence]
              .sort((a, b) => a.collectedAt - b.collectedAt)
              .map((ref) => (
                <li
                  key={ref.evidenceId}
                  className="rounded p-2"
                  style={{
                    background: 'var(--soc-surface-elevated)',
                    border: '1px solid var(--soc-border-subtle)',
                  }}
                >
                  <div className="flex items-center gap-1.5">
                    <OriginBadge origin={ref.origin} />
                    <span className="font-semibold">[{ref.evidenceShortId}] {ref.title}</span>
                  </div>
                  <p className="text-[11px] mt-1" style={{ color: 'var(--soc-text-muted)' }}>
                    {ref.type} · {ref.kind} · investigator: {ref.investigator} · confidence{' '}
                    {Math.round(ref.confidence * 100)}%
                  </p>
                  <p className="text-[11px] mt-0.5" style={{ color: 'var(--soc-text-muted)' }}>
                    Provenance: source: {ref.provenance.sourceLabel || ref.source}; method:{' '}
                    {ref.provenance.method}; collectedBy:{' '}
                    {ref.provenance.collectedBy || ref.investigator}
                    {ref.provenance.adapter ? `; adapter: ${ref.provenance.adapter}` : ''}
                  </p>
                  {ref.summary && <p className="mt-1 text-[11.5px]">{ref.summary}</p>}
                </li>
              ))}
          </ul>
        )}
      </Section>

      <Section title={t('investigation.report.hypotheses', 'Hypotheses')} origin="ai_assessment">
        {report.hypotheses.length === 0 ? (
          <Empty>{t('investigation.report.noHypotheses', 'No hypotheses recorded.')}</Empty>
        ) : (
          <ul className="space-y-2">
            {report.hypotheses.map((section) => (
              <li
                key={section.hypothesis.id}
                className="rounded p-2"
                style={{
                  background: 'var(--soc-surface-elevated)',
                  border: '1px solid var(--soc-border-subtle)',
                }}
              >
                <div className="flex items-center gap-1.5">
                  <OriginBadge origin={section.origin} />
                  <span className="font-semibold">{section.hypothesis.title}</span>
                  <span className="text-[11px] text-[var(--soc-text-muted)]">
                    · {section.hypothesis.status} · {Math.round(section.hypothesis.confidence * 100)}%
                  </span>
                </div>
                <p className="text-[11.5px] mt-1">{section.hypothesis.statement}</p>
                {section.supportingEvidence.length > 0 && (
                  <EvidenceList label="Supporting" items={section.supportingEvidence} />
                )}
                {section.contradictingEvidence.length > 0 && (
                  <EvidenceList label="Contradicting" items={section.contradictingEvidence} />
                )}
                {section.unresolvedQuestions.length > 0 && (
                  <SubList label="Unresolved" items={section.unresolvedQuestions} />
                )}
                {section.challenger && (
                  <div className="mt-1.5 text-[11px]" style={{ color: 'var(--soc-text-muted)' }}>
                    <OriginBadge origin="ai_challenger" /> {section.challenger.summary}
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={t('investigation.report.challenger', 'AI Challenger Findings')} origin="ai_challenger">
        {report.challengerFindings.length === 0 ? (
          <Empty>{t('investigation.report.noChallenger', 'No Challenger findings recorded.')}</Empty>
        ) : (
          <ul className="space-y-1.5">
            {report.challengerFindings.map((finding) => (
              <li
                key={finding.hypothesisId}
                className="rounded p-2"
                style={{
                  background: 'var(--soc-surface-elevated)',
                  border: '1px solid var(--soc-border-subtle)',
                }}
              >
                <OriginBadge origin="ai_challenger" />
                <span className="ml-1 font-semibold">Hypothesis {finding.hypothesisId}</span>
                <p className="text-[11.5px] mt-1">{finding.summary}</p>
                {finding.contradictoryEvidence.length > 0 && (
                  <p className="text-[11px] mt-1">
                    Contradictory evidence:{' '}
                    {finding.contradictoryEvidence
                      .map((ref) => `[E-${evidenceShort(ref.id)}]`)
                      .join(', ')}
                  </p>
                )}
                {finding.alternativeExplanations.length > 0 && (
                  <SubList label="Alternative explanations" items={finding.alternativeExplanations} />
                )}
                {finding.missingEvidence.length > 0 && (
                  <SubList label="Missing evidence" items={finding.missingEvidence} />
                )}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={t('investigation.report.conclusion', 'Final Conclusion')} origin="derived_conclusion">
        {report.finalConclusion.conclusion ? (
          <div>
            <p className="font-semibold">{report.finalConclusion.conclusion.summary}</p>
            {report.finalConclusion.conclusion.rationale && (
              <p className="text-[11.5px] mt-1">{report.finalConclusion.conclusion.rationale}</p>
            )}
            <p className="text-[11px] mt-1" style={{ color: 'var(--soc-text-muted)' }}>
              Confidence: {Math.round(report.finalConclusion.confidence * 100)}% ·{' '}
              {report.finalConclusion.supportingEvidenceIds.length} evidence ·{' '}
              {report.finalConclusion.supportingHypothesisIds.length} hypothesis
            </p>
            {report.finalConclusion.supportingEvidenceIds.length > 0 && (
              <ul className="text-[11px] mt-1">
                {report.finalConclusion.supportingEvidenceIds.map((id) => {
                  const ref = evidenceById.get(id);
                  return ref ? (
                    <li key={id}>
                      [{ref.evidenceShortId}] {ref.title} ({ref.provenance.method})
                    </li>
                  ) : null;
                })}
              </ul>
            )}
          </div>
        ) : (
          <Empty>{t('investigation.report.noConclusion', 'No conclusion has been finalized.')}</Empty>
        )}
      </Section>

      <Section title={t('investigation.report.confidence', 'Confidence Assessment')} origin="ai_assessment">
        <p>
          Overall: {Math.round(report.confidenceAssessment.overall * 100)}% ({report.confidenceAssessment.assessment})
        </p>
        {report.confidenceAssessment.caveats.length > 0 && (
          <SubList label="Caveats" items={report.confidenceAssessment.caveats} />
        )}
      </Section>

      <Section title={t('investigation.report.unresolved', 'Unresolved Questions')} origin="human_context">
        {report.unresolvedQuestions.length === 0 ? (
          <Empty>{t('investigation.report.noUnresolved', 'No unresolved questions recorded.')}</Empty>
        ) : (
          <ul className="list-disc pl-4 space-y-0.5">
            {report.unresolvedQuestions.map((q, idx) => (
              <li key={idx}>{q}</li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={t('investigation.report.actions', 'Actions Taken')} origin="ai_assessment">
        {report.actionsTaken.length === 0 ? (
          <Empty>{t('investigation.report.noActions', 'No actions taken yet.')}</Empty>
        ) : (
          <ul className="space-y-1">
            {report.actionsTaken.slice(0, 10).map((action) => (
              <li key={action.taskId} className="text-[11.5px]">
                <OriginBadge origin={action.origin} />
                <span className="font-semibold ml-1">{action.title}</span>
                <span className="text-[var(--soc-text-muted)]"> · {action.status} · {action.type}</span>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={t('investigation.report.recommendations', 'Recommendations')} origin="ai_assessment">
        <ul className="space-y-1.5">
          {report.recommendations.map((rec, idx) => (
            <li key={idx}>
              <OriginBadge origin={rec.origin} />
              <span className="ml-1">{rec.text}</span>
              <p className="text-[11px] mt-0.5" style={{ color: 'var(--soc-text-muted)' }}>
                {rec.rationale}
              </p>
            </li>
          ))}
        </ul>
      </Section>
    </>
  );
}

function Section({
  title,
  origin,
  children,
}: {
  title: string;
  origin: keyof typeof ORIGIN_BADGE;
  children: React.ReactNode;
}) {
  return (
    <section
      className="rounded-lg p-2.5"
      style={{
        background: 'var(--soc-surface-card)',
        border: '1px solid var(--soc-border-subtle)',
      }}
    >
      <div className="flex items-center gap-1.5 mb-1.5">
        <OriginBadge origin={origin} />
        <h3 className="text-[12px] font-semibold uppercase tracking-wide">{title}</h3>
      </div>
      <div className="space-y-1">{children}</div>
    </section>
  );
}

function SubList({ label, items }: { label: string; items: string[] }) {
  return (
    <div className="mt-1">
      <div className="text-[11px] font-semibold" style={{ color: 'var(--soc-text-secondary)' }}>
        {label}
      </div>
      <ul className="list-disc pl-4 text-[11.5px]">
        {items.map((item, idx) => (
          <li key={idx}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

function EvidenceList({ label, items }: { label: string; items: ReportEvidenceRef[] }) {
  return (
    <div className="mt-1.5">
      <div className="text-[11px] font-semibold" style={{ color: 'var(--soc-text-secondary)' }}>
        {label} evidence
      </div>
      <ul className="space-y-0.5 mt-0.5">
        {items.map((ref) => (
          <li key={ref.evidenceId} className="text-[11.5px]">
            <OriginBadge origin={ref.origin} />
            <span className="ml-1">
              [{ref.evidenceShortId}] {ref.title}
            </span>
            <span className="text-[var(--soc-text-muted)]">
              {' '}
              · source: {ref.provenance.sourceLabel || ref.source} · method: {ref.provenance.method}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return <p className="text-[11.5px]" style={{ color: 'var(--soc-text-muted)' }}>{children}</p>;
}

function OriginBadge({ origin }: { origin: keyof typeof ORIGIN_BADGE }) {
  const meta = ORIGIN_BADGE[origin] || ORIGIN_BADGE.observed_evidence;
  const palette: Record<string, { bg: string; fg: string; border: string }> = {
    observed: { bg: 'var(--soc-info-muted)', fg: 'var(--soc-info-main)', border: 'var(--soc-info-main)' },
    human: { bg: 'var(--soc-warning-muted)', fg: 'var(--soc-warning-main)', border: 'var(--soc-warning-main)' },
    humanContext: { bg: 'var(--soc-warning-muted)', fg: 'var(--soc-warning-main)', border: 'var(--soc-warning-main)' },
    ai: { bg: 'var(--soc-ai-muted)', fg: 'var(--soc-ai-primary)', border: 'var(--soc-ai-primary)' },
    aiChallenger: { bg: 'var(--soc-danger-muted)', fg: 'var(--soc-danger-main)', border: 'var(--soc-danger-main)' },
    derived: { bg: 'var(--soc-success-muted)', fg: 'var(--soc-success-main)', border: 'var(--soc-success-main)' },
  };
  const paletteEntry = palette[meta.tone] || palette.observed;
  return (
    <span
      className="inline-block text-[9.5px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded"
      style={{
        background: paletteEntry.bg,
        color: paletteEntry.fg,
        border: `1px solid ${paletteEntry.border}`,
      }}
    >
      {meta.label}
    </span>
  );
}

function evidenceShort(id: string): string {
  return id.replace(/-/g, '').slice(0, 8).toUpperCase();
}
