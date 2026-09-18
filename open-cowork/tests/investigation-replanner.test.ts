import { describe, expect, it } from 'vitest';
import { InvestigationReplanner, NextBestWorkSelector } from '../src/main/investigation/investigation-replanner';
import { AgentCapabilityRegistry } from '../src/main/investigation/parallel-investigation-engine';
import type { Investigation } from '../src/shared/cyber/investigation-types';

function makeInvestigation(): Investigation {
  const now = 1_700_000_000_000;
  return {
    id: 'inv-1',
    title: 'Service account investigation',
    objective: 'Determine whether service account X was misused for lateral movement',
    status: 'REPLANNING',
    createdAt: now,
    updatedAt: now,
    humanContext: 'Service accounts are used widely in this environment',
    humanCapabilityContext: {
      environmentalKnowledge: [],
      priorities: [{ id: 'p1', value: 'Determine whether service account X normally authenticates from host Y.', createdAt: now }],
      constraints: [],
      suspicions: [{ id: 's1', value: 'Possible lateral movement via service account', createdAt: now }],
      knownLegitimateBehavior: [{ id: 'k1', value: 'Approved backup jobs use service accounts on weekends', createdAt: now }],
      knownAbnormalBehavior: [],
      riskTolerance: 'LOW',
      importantEntityIds: [],
      importantEntities: [],
      investigationDirections: [],
      notes: [],
    },
    hypotheses: [
      {
        id: 'hyp-a',
        title: 'Credential theft',
        statement: 'The service account was abused by an attacker',
        status: 'SUPPORTED',
        confidence: 0.62,
        confidenceAssessment: 'MEDIUM',
        supportingEvidenceIds: ['e-1'],
        contradictingEvidenceIds: ['e-2'],
        assumptions: ['Assume unusual host access is not routine'],
        unresolvedQuestions: ['Does this account normally authenticate from host Y?'],
        createdBy: 'human',
        createdAt: now,
        updatedAt: now,
      },
      {
        id: 'hyp-b',
        title: 'Routine maintenance',
        statement: 'The service account activity was part of normal maintenance',
        status: 'OPEN',
        confidence: 0.58,
        confidenceAssessment: 'MEDIUM',
        supportingEvidenceIds: ['e-2'],
        contradictingEvidenceIds: [],
        assumptions: ['Known scheduled jobs may explain the host pattern'],
        unresolvedQuestions: ['Was there an approved backup run on this host?'],
        createdBy: 'human',
        createdAt: now,
        updatedAt: now,
      },
    ],
    evidence: [
      {
        id: 'e-1',
        investigationId: 'inv-1',
        type: 'OBSERVATION',
        title: 'Unexpected authentication from host Y',
        source: 'auth.log',
        timestamp: now,
        collectedAt: now,
        investigator: 'Identity Investigator',
        relatedEntityIds: [],
        content: 'Service account X authenticated from host Y.',
        confidence: 0.9,
        provenance: { method: 'tool_output', sourceType: 'log' },
        hypothesisIds: ['hyp-a'],
        analystAnnotations: [],
        relationships: [],
        kind: 'log_excerpt',
        summary: 'Unexpected host authentication',
        tags: ['identity'],
      },
      {
        id: 'e-2',
        investigationId: 'inv-1',
        type: 'OBSERVATION',
        title: 'Maintenance schedule overlap',
        source: 'change-ticket',
        timestamp: now + 100,
        collectedAt: now + 100,
        investigator: 'Historical Investigator',
        relatedEntityIds: [],
        content: 'A maintenance window overlaps the observed activity.',
        confidence: 0.78,
        provenance: { method: 'imported', sourceType: 'file' },
        hypothesisIds: ['hyp-a', 'hyp-b'],
        analystAnnotations: [],
        relationships: [],
        kind: 'note',
        summary: 'Potential benign explanation exists',
        tags: ['history'],
      },
    ],
    entities: [],
    graph: { relationships: [] },
    timeline: [],
    openQuestions: ['Is host Y part of the normal backup path?'],
    aiTasks: [],
    humanTasks: [],
    decisions: [],
    conclusions: [],
    confidence: 0,
    activity: [],
  };
}

describe('InvestigationReplanner', () => {
  it('assesses uncertainty from competing hypotheses, missing evidence, risk, and capabilities', () => {
    const replanner = new InvestigationReplanner();
    const assessment = replanner.assessUncertainty(makeInvestigation());

    expect(assessment.competingHypotheses).toHaveLength(2);
    expect(assessment.summary).toContain('does not fully distinguish');
    expect(assessment.humanPriorities[0]).toContain('normally authenticates from host Y');
    expect(assessment.risk.requiresChallenge).toBe(true);
    expect(assessment.availableCapabilities).toContain('Challenger');
    expect(assessment.missingEvidence.some((item) => item.includes('No contradictory evidence') || item.includes('Unresolved question'))).toBe(true);
  });

  it('selects next best work that is likely to reduce uncertainty', () => {
    const investigation = makeInvestigation();
    const replanner = new InvestigationReplanner();
    const assessment = replanner.assessUncertainty(investigation);
    const selector = new NextBestWorkSelector();
    const recommendation = selector.select(
      investigation,
      assessment,
      new AgentCapabilityRegistry().selectRolesForInvestigation(investigation)
    );

    expect(recommendation.uncertaintyReductionGoal).toContain('Reduce uncertainty');
    expect(recommendation.recommendedTasks.length).toBeGreaterThan(0);
    expect(
      recommendation.recommendedTasks.some(
        (task) =>
          task.role === 'Historical Investigator' ||
          /reduce uncertainty|normal|historical|authenticate|host/i.test(task.description)
      )
    ).toBe(true);
  });

  it('creates a replan that prepends next-best-work recommendations to the base plan', () => {
    const replanner = new InvestigationReplanner();
    const replan = replanner.createReplan(makeInvestigation());

    expect(replan.summary).toContain('Replanning focus');
    expect(replan.uncertainty.summary).toContain('does not fully distinguish');
    expect(replan.nextBestWork.recommendedTasks.length).toBeGreaterThan(0);
    expect(replan.tasks.length).toBeGreaterThanOrEqual(replan.nextBestWork.recommendedTasks.length);
  });
});
