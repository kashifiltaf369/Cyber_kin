import type { InvestigationReport, ReportEvidenceRef, ReportOrigin } from './investigation-report-service';

function shortId(id: string): string {
  return id.replace(/-/g, '').slice(0, 8).toUpperCase();
}

const ORIGIN_LABEL: Record<ReportOrigin, string> = {
  observed_evidence: 'OBSERVED EVIDENCE',
  human_decision: 'HUMAN DECISION',
  human_context: 'HUMAN CONTEXT',
  ai_assessment: 'AI ASSESSMENT',
  ai_challenger: 'AI CHALLENGER',
  derived_conclusion: 'DERIVED CONCLUSION',
};

function fmtTimestamp(value: number | undefined): string {
  if (!value || Number.isNaN(value)) return 'unknown';
  return new Date(value).toISOString();
}

function listOrNone(items: string[], emptyMessage: string): string {
  if (items.length === 0) return emptyMessage;
  return items.map((item) => `- ${item}`).join('\n');
}

function evidenceShortLabel(ref: ReportEvidenceRef): string {
  return `[E-${ref.evidenceShortId}] ${ref.title}`;
}

function evidenceProvenance(ref: ReportEvidenceRef): string {
  const provenance = ref.provenance;
  const sourceLabel = provenance?.sourceLabel || ref.source || 'unknown';
  const method = provenance?.method || 'unspecified';
  const adapter = provenance?.adapter ? ` via ${provenance.adapter}` : '';
  const capability = provenance?.capability ? ` (capability: ${provenance.capability})` : '';
  const collectedBy = provenance?.collectedBy || ref.investigator || 'unspecified';
  return `source: ${sourceLabel}; method: ${method}; collectedBy: ${collectedBy}${adapter}${capability}`;
}

export function renderInvestigationReportMarkdown(report: InvestigationReport): string {
  const lines: string[] = [];

  lines.push(`# Cybersecurity Investigation Report`);
  lines.push('');
  lines.push(`**Investigation ID:** \`${report.investigationId}\``);
  lines.push(`**Title:** ${report.title}`);
  lines.push(`**Status:** ${report.status}`);
  lines.push(`**Objective:** ${report.objective}`);
  lines.push(`**Created:** ${fmtTimestamp(report.createdAt)}`);
  lines.push(`**Updated:** ${fmtTimestamp(report.updatedAt)}`);
  lines.push(`**Report Generated:** ${fmtTimestamp(report.generatedAt)}`);
  lines.push('');
  lines.push(
    '> This report distinguishes AI-generated assessment, human decisions, and observed evidence. Every conclusion cites supporting evidence or hypotheses. No evidence is fabricated.'
  );
  lines.push('');

  lines.push(`## 1. Executive Summary`);
  lines.push('');
  lines.push(`Origin: **${ORIGIN_LABEL[report.executiveSummary.origin]}**`);
  lines.push('');
  lines.push(report.executiveSummary.text);
  lines.push('');
  if (report.executiveSummary.supportingHypothesisIds.length > 0) {
    lines.push(`Supporting hypotheses: ${report.executiveSummary.supportingHypothesisIds.map((id) => `\`${id}\``).join(', ')}`);
  }
  if (report.executiveSummary.supportingEvidenceIds.length > 0) {
    const refs = report.executiveSummary.supportingEvidenceIds
      .map((id) => report.evidence.find((ref) => ref.evidenceId === id))
      .filter((ref): ref is ReportEvidenceRef => Boolean(ref));
    lines.push(`Supporting evidence: ${refs.map((ref) => `\`${ref.evidenceShortId}\``).join(', ')}`);
  }
  lines.push(`Confidence: ${Math.round(report.executiveSummary.confidence * 100)}%`);
  lines.push('');

  lines.push(`## 2. Investigation Objective`);
  lines.push('');
  lines.push(report.objective);
  lines.push('');

  lines.push(`## 3. Human Analyst Context`);
  lines.push('');
  lines.push(`Origin: **${ORIGIN_LABEL[report.humanContext.origin]}**`);
  lines.push('');
  lines.push(`**Risk Tolerance:** ${report.humanContext.riskTolerance}`);
  lines.push('');
  lines.push(`### Priorities`);
  lines.push(listOrNone(report.humanContext.priorities, '- none recorded'));
  lines.push('');
  lines.push(`### Constraints`);
  lines.push(listOrNone(report.humanContext.constraints, '- none recorded'));
  lines.push('');
  lines.push(`### Suspicions`);
  lines.push(listOrNone(report.humanContext.suspicions, '- none recorded'));
  lines.push('');
  lines.push(`### Known Legitimate Behavior`);
  lines.push(listOrNone(report.humanContext.knownLegitimateBehavior, '- none recorded'));
  lines.push('');
  lines.push(`### Known Abnormal Behavior`);
  lines.push(listOrNone(report.humanContext.knownAbnormalBehavior, '- none recorded'));
  lines.push('');
  lines.push(`### Important Entities (flagged by human)`);
  if (report.humanContext.importantEntities.length === 0) {
    lines.push('- none recorded');
  } else {
    for (const entity of report.humanContext.importantEntities) {
      lines.push(`- **${entity.name}** (${entity.type})${entity.summary ? `: ${entity.summary}` : ''}`);
    }
  }
  lines.push('');
  if (report.humanContext.rawNotes && report.humanContext.rawNotes.trim().length > 0) {
    lines.push(`### Analyst Notes`);
    lines.push('```');
    lines.push(report.humanContext.rawNotes);
    lines.push('```');
    lines.push('');
  }

  lines.push(`## 4. Timeline`);
  lines.push('');
  if (report.timeline.length === 0) {
    lines.push('_No timeline events recorded._');
  } else {
    const ordered = [...report.timeline].sort((a, b) => a.occurredAt - b.occurredAt);
    lines.push(`| Time | Event |`);
    lines.push(`| --- | --- |`);
    for (const entry of ordered) {
      lines.push(`| ${fmtTimestamp(entry.occurredAt)} | ${entry.summary} (${entry.eventType || 'EVENT'}) |`);
    }
  }
  lines.push('');

  lines.push(`## 5. Key Entities`);
  lines.push('');
  if (report.keyEntities.length === 0) {
    lines.push('_No entities recorded._');
  } else {
    lines.push(`| Entity | Type | Linked Evidence |`);
    lines.push(`| --- | --- | --- |`);
    for (const entry of report.keyEntities) {
      lines.push(`| ${entry.entity.name} | ${entry.entity.type} | ${entry.linkedEvidenceCount} |`);
    }
  }
  lines.push('');

  lines.push(`## 6. Evidence`);
  lines.push('');
  if (report.evidence.length === 0) {
    lines.push('_No evidence has been collected._');
  } else {
    lines.push(`Total evidence items: **${report.evidence.length}**`);
    lines.push('');
    const ordered = [...report.evidence].sort((a, b) => a.collectedAt - b.collectedAt);
    for (const ref of ordered) {
      lines.push(`### [E-${ref.evidenceShortId}] ${ref.title}`);
      lines.push('');
      lines.push(`Origin: **${ORIGIN_LABEL[ref.origin]}**`);
      lines.push('');
      lines.push(`- Type: ${ref.type}`);
      lines.push(`- Kind: ${ref.kind}`);
      lines.push(`- Investigator: ${ref.investigator}`);
      lines.push(`- Confidence: ${Math.round(ref.confidence * 100)}%`);
      lines.push(`- Collected At: ${fmtTimestamp(ref.collectedAt)}`);
      lines.push(`- Tags: ${ref.tags.length > 0 ? ref.tags.map((tag) => `\`${tag}\``).join(', ') : '_none_'}`);
      lines.push(`- Linked Hypotheses: ${ref.hypothesisIds.length > 0 ? ref.hypothesisIds.map((id) => `\`${id}\``).join(', ') : '_none_'}`);
      lines.push(`- Provenance: ${evidenceProvenance(ref)}`);
      lines.push('');
      if (ref.summary) {
        lines.push(`**Summary:** ${ref.summary}`);
        lines.push('');
      }
    }
  }

  lines.push(`## 7. Hypotheses`);
  lines.push('');
  if (report.hypotheses.length === 0) {
    lines.push('_No hypotheses recorded._');
  } else {
    for (const section of report.hypotheses) {
      const hyp = section.hypothesis;
      lines.push(`### ${hyp.title}`);
      lines.push('');
      lines.push(`Origin: **${ORIGIN_LABEL[section.origin]}**`);
      lines.push('');
      lines.push(`Statement: ${hyp.statement}`);
      lines.push('');
      lines.push(`- Status: ${hyp.status}`);
      lines.push(`- Confidence: ${Math.round(hyp.confidence * 100)}% (${hyp.confidenceAssessment})`);
      lines.push('');
      lines.push(`#### Supporting Evidence`);
      if (section.supportingEvidence.length === 0) {
        lines.push('- _No supporting evidence linked._');
      } else {
        for (const ref of section.supportingEvidence) {
          lines.push(`- ${evidenceShortLabel(ref)} (${ORIGIN_LABEL[ref.origin]}, ${evidenceProvenance(ref)})`);
        }
      }
      lines.push('');
      lines.push(`#### Contradicting Evidence`);
      if (section.contradictingEvidence.length === 0) {
        lines.push('- _No contradicting evidence linked._');
      } else {
        for (const ref of section.contradictingEvidence) {
          lines.push(`- ${evidenceShortLabel(ref)} (${ORIGIN_LABEL[ref.origin]}, ${evidenceProvenance(ref)})`);
        }
      }
      lines.push('');
      if (section.assumptions.length > 0) {
        lines.push(`#### Assumptions`);
        lines.push(listOrNone(section.assumptions, '- _none_'));
        lines.push('');
      }
      if (section.unresolvedQuestions.length > 0) {
        lines.push(`#### Unresolved Questions`);
        lines.push(listOrNone(section.unresolvedQuestions, '- _none_'));
        lines.push('');
      }
    }
  }

  lines.push(`## 8. AI Challenger Findings`);
  lines.push('');
  if (report.challengerFindings.length === 0) {
    lines.push('_No Challenger findings recorded._');
  } else {
    for (const finding of report.challengerFindings) {
      const linkedHypothesis = report.hypotheses.find((section) => section.hypothesis.id === finding.hypothesisId);
      lines.push(`### Hypothesis: ${linkedHypothesis?.hypothesis.title || finding.hypothesisId}`);
      lines.push('');
      lines.push(`Origin: **${ORIGIN_LABEL.ai_challenger}**`);
      lines.push('');
      lines.push(finding.summary);
      lines.push('');
      lines.push(`#### Contradictory Evidence`);
      if (finding.contradictoryEvidence.length === 0) {
        lines.push('- _none_');
      } else {
        for (const ev of finding.contradictoryEvidence) {
          lines.push(`- [E-${shortId(ev.id)}] ${ev.title}`);
        }
      }
      lines.push('');
      lines.push(`#### Weak Assumptions`);
      lines.push(listOrNone(finding.weakAssumptions, '- _none_'));
      lines.push('');
      lines.push(`#### Alternative Explanations`);
      lines.push(listOrNone(finding.alternativeExplanations, '- _none_'));
      lines.push('');
      lines.push(`#### Falsification Questions`);
      lines.push(listOrNone(finding.falsificationQuestions, '- _none_'));
      lines.push('');
      lines.push(`#### Missing Evidence`);
      lines.push(listOrNone(finding.missingEvidence, '- _none_'));
      lines.push('');
    }
  }

  lines.push(`## 9. Final Conclusion`);
  lines.push('');
  if (!report.finalConclusion.conclusion) {
    lines.push(`Origin: **${ORIGIN_LABEL.ai_assessment}**`);
    lines.push('');
    lines.push('_No conclusion has been finalized. AI assessment pending._');
  } else {
    lines.push(`Origin: **${ORIGIN_LABEL[report.finalConclusion.origin]}**`);
    lines.push('');
    lines.push(`**Summary:** ${report.finalConclusion.conclusion.summary}`);
    lines.push('');
    if (report.finalConclusion.conclusion.rationale) {
      lines.push(`**Rationale:** ${report.finalConclusion.conclusion.rationale}`);
      lines.push('');
    }
    lines.push(`Confidence: ${Math.round(report.finalConclusion.confidence * 100)}%`);
    lines.push('');
    lines.push(`Supporting Hypotheses:`);
    if (report.finalConclusion.supportingHypothesisIds.length === 0) {
      lines.push('- _none linked_');
    } else {
      for (const id of report.finalConclusion.supportingHypothesisIds) {
        lines.push(`- \`${id}\``);
      }
    }
    lines.push('');
    lines.push(`Supporting Evidence:`);
    const finalRefs = report.finalConclusion.supportingEvidenceIds
      .map((id) => report.evidence.find((ref) => ref.evidenceId === id))
      .filter((ref): ref is ReportEvidenceRef => Boolean(ref));
    if (finalRefs.length === 0) {
      lines.push('- _none linked_');
    } else {
      for (const ref of finalRefs) {
        lines.push(`- ${evidenceShortLabel(ref)}`);
      }
    }
    lines.push('');
  }

  lines.push(`## 10. Confidence Assessment`);
  lines.push('');
  lines.push(`Origin: **${ORIGIN_LABEL[report.confidenceAssessment.origin]}**`);
  lines.push('');
  lines.push(`- Overall Confidence: ${Math.round(report.confidenceAssessment.overall * 100)}% (${report.confidenceAssessment.assessment})`);
  lines.push(`- Supporting Evidence: ${report.confidenceAssessment.supportingEvidenceIds.length > 0 ? report.confidenceAssessment.supportingEvidenceIds.map((id) => `\`${id}\``).join(', ') : '_none_'}`);
  lines.push(`- Supporting Hypotheses: ${report.confidenceAssessment.supportingHypothesisIds.length > 0 ? report.confidenceAssessment.supportingHypothesisIds.map((id) => `\`${id}\``).join(', ') : '_none_'}`);
  if (report.confidenceAssessment.caveats.length > 0) {
    lines.push('');
    lines.push(`**Caveats:**`);
    for (const caveat of report.confidenceAssessment.caveats) {
      lines.push(`- ${caveat}`);
    }
  }
  lines.push('');

  lines.push(`## 11. Unresolved Questions`);
  lines.push('');
  if (report.unresolvedQuestions.length === 0) {
    lines.push('_No unresolved questions recorded._');
  } else {
    for (const question of report.unresolvedQuestions) {
      lines.push(`- ${question}`);
    }
  }
  lines.push('');

  lines.push(`## 12. Actions Taken`);
  lines.push('');
  if (report.actionsTaken.length === 0) {
    lines.push('_No actions taken yet._');
  } else {
    for (const action of report.actionsTaken) {
      lines.push(`### [${action.type === 'HUMAN' ? 'HUMAN DECISION' : 'AI TASK'}] ${action.title}`);
      lines.push('');
      lines.push(`Origin: **${ORIGIN_LABEL[action.origin]}**`);
      lines.push('');
      if (action.description) lines.push(action.description);
      lines.push(`- Status: ${action.status}`);
      lines.push(`- Created: ${fmtTimestamp(action.createdAt)}`);
      lines.push(`- Updated: ${fmtTimestamp(action.updatedAt)}`);
      if (action.owner) lines.push(`- Owner: ${action.owner}`);
      if (action.supportingEvidenceIds.length > 0) {
        lines.push(`- Produced Evidence: ${action.supportingEvidenceIds.map((id) => `\`${id}\``).join(', ')}`);
      }
      lines.push('');
    }
  }

  lines.push(`## 13. Human Decisions`);
  lines.push('');
  if (report.humanContext.decisions.length === 0) {
    lines.push('_No human decisions recorded._');
  } else {
    for (const decision of report.humanContext.decisions) {
      lines.push(`### ${fmtTimestamp(decision.createdAt)}: ${decision.summary}`);
      lines.push('');
      if (decision.rationale) lines.push(`Rationale: ${decision.rationale}`);
      lines.push('');
    }
  }

  lines.push(`## 14. Recommendations`);
  lines.push('');
  for (const rec of report.recommendations) {
    lines.push(`- **${ORIGIN_LABEL[rec.origin]}:** ${rec.text}`);
    lines.push(`  - Rationale: ${rec.rationale}`);
    if (rec.linkedHypothesisIds.length > 0) {
      lines.push(`  - Linked Hypotheses: ${rec.linkedHypothesisIds.map((id) => `\`${id}\``).join(', ')}`);
    }
    if (rec.linkedEvidenceIds.length > 0) {
      lines.push(`  - Linked Evidence: ${rec.linkedEvidenceIds.map((id) => `\`${id}\``).join(', ')}`);
    }
  }
  lines.push('');

  lines.push(`## 15. Evidence Provenance Index`);
  lines.push('');
  if (report.evidence.length === 0) {
    lines.push('_No evidence to enumerate._');
  } else {
    lines.push(`| Evidence | Origin | Provenance |`);
    lines.push(`| --- | --- | --- |`);
    for (const ref of report.evidence) {
      lines.push(`| [E-${ref.evidenceShortId}] ${ref.title} | ${ORIGIN_LABEL[ref.origin]} | ${evidenceProvenance(ref)} |`);
    }
  }
  lines.push('');
  lines.push('_End of report._');

  return lines.join('\n');
}
