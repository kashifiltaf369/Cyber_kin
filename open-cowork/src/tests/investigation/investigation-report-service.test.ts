import { describe, it, expect } from 'vitest';
import { InvestigationReportService } from '../../main/investigation/investigation-report-service';
import { renderInvestigationReportMarkdown } from '../../main/investigation/investigation-report-markdown';
import type {
  Investigation,
  InvestigationEvidence,
  InvestigationHypothesis,
} from '../../shared/cyber/investigation-types';

const NOW = 1_700_000_000_000;

function makeEvidence(overrides: Partial<InvestigationEvidence> = {}): InvestigationEvidence {
  return {
    id: 'ev-1',
    investigationId: 'inv-1',
    type: 'OBSERVATION',
    title: 'Suspicious process spawn',
    source: 'edr.log',
    timestamp: NOW - 1000,
    collectedAt: NOW - 1000,
    investigator: 'agent',
    relatedEntityIds: ['ent-host-1'],
    content: 'spawned by powershell.exe',
    confidence: 0.8,
    provenance: {
      method: 'agent_observed',
      sourceType: 'log',
      sourceId: 'edr-1234',
      sourceLabel: 'EDR log excerpt',
      collectedBy: 'agent:detective',
      adapter: 'edr-adapter',
      capability: 'log_query',
    },
    hypothesisIds: [],
    analystAnnotations: [],
    relationships: [],
    kind: 'log_excerpt',
    summary: 'PowerShell spawned by Word macro.',
    tags: ['process', 'powershell'],
    ...overrides,
  };
}

function makeHypothesis(overrides: Partial<InvestigationHypothesis> = {}): InvestigationHypothesis {
  return {
    id: 'hyp-1',
    title: 'Phishing via macro',
    statement: 'User opened malicious Office document that launched PowerShell.',
    status: 'SUPPORTED',
    confidence: 0.7,
    confidenceAssessment: 'MEDIUM',
    supportingEvidenceIds: ['ev-1'],
    contradictingEvidenceIds: [],
    assumptions: [],
    unresolvedQuestions: ['Did AV block the macro?'],
    createdBy: 'agent',
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
}

function makeInvestigation(overrides: Partial<Investigation> = {}): Investigation {
  return {
    id: 'inv-1',
    title: 'Suspected phishing incident',
    objective: 'Determine if macro-driven phishing occurred.',
    status: 'INVESTIGATING',
    createdAt: NOW - 5000,
    updatedAt: NOW,
    humanContext: 'Priority: contain endpoint.',
    humanCapabilityContext: {
      environmentalKnowledge: [],
      priorities: [{ id: 'p1', value: 'Contain endpoint', createdAt: NOW }],
      constraints: [{ id: 'c1', value: 'Do not disconnect production DB', createdAt: NOW }],
      suspicions: [{ id: 's1', value: 'User received suspicious email', createdAt: NOW }],
      knownLegitimateBehavior: [{ id: 'k1', value: 'IT runs PowerShell scripts', createdAt: NOW }],
      knownAbnormalBehavior: [{ id: 'a1', value: 'Word spawning PowerShell', createdAt: NOW }],
      riskTolerance: 'MEDIUM',
      importantEntityIds: [],
      importantEntities: [],
      investigationDirections: [],
      notes: [],
    },
    hypotheses: [makeHypothesis()],
    evidence: [makeEvidence()],
    entities: [
      { id: 'ent-host-1', name: 'WORKSTATION-01', type: 'host', createdAt: NOW },
    ],
    graph: { relationships: [] },
    timeline: [
      { id: 't1', summary: 'Investigation opened', occurredAt: NOW - 4000, eventType: 'INVESTIGATION_OPENED' },
    ],
    openQuestions: ['Isolate or monitor?'],
    aiTasks: [],
    humanTasks: [],
    decisions: [],
    conclusions: [],
    confidence: 0,
    activity: [],
    ...overrides,
  };
}

describe('InvestigationReportService', () => {
  it('builds a structured report with required sections and never fabricates evidence', () => {
    const service = new InvestigationReportService();
    const report = service.buildReport(makeInvestigation(), NOW + 1000);

    expect(report.executiveSummary.text).toMatch(/Suspected phishing incident/);
    expect(report.executiveSummary.text).toContain('Assessment stage:');
    expect(report.evidence).toHaveLength(1);
    expect(report.hypotheses).toHaveLength(1);
    expect(report.hypotheses[0].supportingEvidence).toHaveLength(1);
    expect(report.hypotheses[0].contradictingEvidence).toHaveLength(0);
    expect(report.hypotheses[0].unresolvedQuestions).toContain('Did AV block the macro?');
    expect(report.evidence[0].evidenceShortId).toMatch(/^[A-Z0-9]{1,8}$/);
    expect(report.evidence[0].provenance.method).toBe('agent_observed');
    expect(report.evidence[0].provenance.sourceLabel).toBe('EDR log excerpt');
    expect(report.confidenceAssessment.supportingEvidenceIds).toEqual([]);
    expect(report.finalConclusion.conclusion).toBeNull();
    expect(report.actionsTaken).toEqual([]);
  });

  it('flags observations vs human decisions vs AI assessments by origin', () => {
    const investigation = makeInvestigation({
      evidence: [
        makeEvidence({ id: 'ev-1', provenance: { method: 'agent_observed', sourceType: 'log' } }),
        makeEvidence({
          id: 'ev-2',
          type: 'OBSERVATION',
          title: 'Analyst note from SOC',
          investigator: 'human',
          provenance: { method: 'human_reported', sourceType: 'human_input' },
        }),
      ],
      hypotheses: [
        makeHypothesis({ id: 'hyp-human', createdBy: 'human', supportingEvidenceIds: ['ev-2'] }),
        makeHypothesis({ id: 'hyp-agent', createdBy: 'agent', supportingEvidenceIds: ['ev-1'] }),
      ],
    });
    const report = new InvestigationReportService().buildReport(investigation);
    const ev1 = report.evidence.find((ref) => ref.evidenceId === 'ev-1');
    const ev2 = report.evidence.find((ref) => ref.evidenceId === 'ev-2');
    expect(ev1?.origin).toBe('observed_evidence');
    expect(ev2?.origin).toBe('human_decision');
    expect(report.hypotheses.find((section) => section.hypothesis.id === 'hyp-human')?.origin).toBe('human_decision');
    expect(report.hypotheses.find((section) => section.hypothesis.id === 'hyp-agent')?.origin).toBe('ai_assessment');
  });

  it('attaches Challenger findings to every hypothesis and links existing contradictory evidence only', () => {
    const investigation = makeInvestigation({
      hypotheses: [
        makeHypothesis({
          id: 'hyp-A',
          contradictingEvidenceIds: ['ev-1'],
          title: 'Hypothesis A',
        }),
      ],
    });
    const report = new InvestigationReportService().buildReport(investigation);
    expect(report.challengerFindings).toHaveLength(1);
    expect(report.challengerFindings[0].hypothesisId).toBe('hyp-A');
    expect(report.challengerFindings[0].contradictoryEvidence).toHaveLength(1);
    expect(report.challengerFindings[0].contradictoryEvidence[0].id).toBe('ev-1');
    const section = report.hypotheses[0];
    expect(section.challenger).not.toBeNull();
  });

  it('renders executive summary with confidence and supporting references when conclusion exists', () => {
    const investigation = makeInvestigation({
      conclusions: [
        {
          id: 'c1',
          summary: 'Phishing confirmed.',
          confidence: 0.85,
          derivedFromHypothesisIds: ['hyp-1'],
          derivedFromEvidenceIds: ['ev-1'],
          rationale: 'Macro matched known template.',
          createdAt: NOW,
          updatedAt: NOW,
        },
      ],
    });
    const report = new InvestigationReportService().buildReport(investigation);
    expect(report.executiveSummary.text).toContain('Phishing confirmed.');
    expect(report.executiveSummary.supportingEvidenceIds).toEqual(['ev-1']);
    expect(report.executiveSummary.supportingHypothesisIds).toEqual(['hyp-1']);
    expect(report.confidenceAssessment.overall).toBeGreaterThan(0.8);
    expect(report.confidenceAssessment.assessment).toBe('HIGH');
    expect(report.finalConclusion.conclusion?.id).toBe('c1');
  });

  it('does not fabricate evidence — unknown linked evidence IDs are dropped from report sections', () => {
    const investigation = makeInvestigation({
      hypotheses: [
        makeHypothesis({
          id: 'hyp-x',
          title: 'Phantom',
          supportingEvidenceIds: ['ev-1', 'ev-DOES-NOT-EXIST'],
          contradictingEvidenceIds: ['ev-also-missing'],
        }),
      ],
    });
    const report = new InvestigationReportService().buildReport(investigation);
    const section = report.hypotheses.find((s) => s.hypothesis.id === 'hyp-x');
    expect(section?.supportingEvidence).toHaveLength(1);
    expect(section?.contradictingEvidence).toHaveLength(0);
    expect(section?.supportingEvidence[0].evidenceId).toBe('ev-1');
  });
});

describe('renderInvestigationReportMarkdown', () => {
  it('produces all required sections, distinguishes origins, and includes provenance for cited evidence', () => {
    const investigation = makeInvestigation({
      conclusions: [
        {
          id: 'c1',
          summary: 'Phishing confirmed.',
          confidence: 0.8,
          derivedFromHypothesisIds: ['hyp-1'],
          derivedFromEvidenceIds: ['ev-1'],
          createdAt: NOW,
          updatedAt: NOW,
        },
      ],
      decisions: [{ id: 'd1', summary: 'Isolate endpoint', rationale: 'Prevents spread', createdAt: NOW }],
    });
    const report = new InvestigationReportService().buildReport(investigation);
    const md = renderInvestigationReportMarkdown(report);

    const required = [
      '# Cybersecurity Investigation Report',
      '## 1. Executive Summary',
      '## 2. Investigation Objective',
      '## 3. Human Analyst Context',
      '## 4. Timeline',
      '## 5. Key Entities',
      '## 6. Evidence',
      '## 7. Hypotheses',
      '## 8. AI Challenger Findings',
      '## 9. Final Conclusion',
      '## 10. Confidence Assessment',
      '## 11. Unresolved Questions',
      '## 12. Actions Taken',
      '## 13. Human Decisions',
      '## 14. Recommendations',
      '## 15. Evidence Provenance Index',
    ];
    for (const heading of required) {
      expect(md).toContain(heading);
    }

    expect(md).toContain('OBSERVED EVIDENCE');
    expect(md).toContain('HUMAN DECISION');
    expect(md).toContain('AI CHALLENGER');
    expect(md).toContain('source: EDR log excerpt');
    expect(md).toContain('Isolate endpoint');
  });

  it('does not invent evidence when none exists — every section shows explicit empty state', () => {
    const investigation = makeInvestigation({
      evidence: [],
      hypotheses: [],
      conclusions: [],
      decisions: [],
      openQuestions: [],
      entities: [],
      timeline: [],
    });
    const report = new InvestigationReportService().buildReport(investigation);
    const md = renderInvestigationReportMarkdown(report);

    expect(md).toContain('_No evidence has been collected._');
    expect(md).toContain('_No hypotheses recorded._');
    expect(md).toContain('_No Challenger findings recorded._');
    expect(md).toContain('_No conclusion has been finalized.');
    expect(md).toContain('_No entities recorded._');
    expect(md).toContain('_No timeline events recorded._');
    expect(md).toContain('_No unresolved questions recorded._');
    expect(md).toContain('_No actions taken yet._');
    expect(md).toContain('_No human decisions recorded._');
  });
});
