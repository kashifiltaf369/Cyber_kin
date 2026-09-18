import { describe, expect, it } from 'vitest';
import { ChallengerAgent } from '../src/main/investigation/challenger-agent';
import type { Investigation } from '../src/shared/cyber/investigation-types';

function makeInvestigation(): Investigation {
  const now = 1_700_000_000_000;
  return {
    id: 'inv-1',
    title: 'Case',
    objective: 'Obj',
    status: 'INVESTIGATING',
    createdAt: now,
    updatedAt: now,
    humanContext: '',
    humanCapabilityContext: {
      environmentalKnowledge: [],
      priorities: [],
      constraints: [],
      suspicions: [],
      knownLegitimateBehavior: [{ id: 'legit-1', value: 'Daily admin PowerShell maintenance', createdAt: now }],
      knownAbnormalBehavior: [],
      riskTolerance: 'MEDIUM',
      importantEntityIds: [],
      importantEntities: [],
      investigationDirections: [],
      notes: [],
    },
    hypotheses: [
      {
        id: 'hyp-1',
        title: 'Malicious document execution',
        statement: 'Office spawned malicious execution',
        status: 'SUPPORTED',
        confidence: 0.78,
        confidenceAssessment: 'HIGH',
        supportingEvidenceIds: ['e-1'],
        contradictingEvidenceIds: ['e-2'],
        assumptions: ['Assume Office spawning PowerShell is always malicious'],
        unresolvedQuestions: ['Was there a signed admin macro?'],
        createdBy: 'agent',
        createdAt: now,
        updatedAt: now,
      },
    ],
    evidence: [
      {
        id: 'e-1',
        investigationId: 'inv-1',
        type: 'OBSERVATION',
        title: 'Word spawned PowerShell',
        source: 'process-tree',
        timestamp: now,
        collectedAt: now,
        investigator: 'Endpoint Investigator',
        relatedEntityIds: [],
        content: 'Word spawned PowerShell',
        confidence: 0.9,
        provenance: { method: 'tool_output', sourceType: 'file' },
        hypothesisIds: ['hyp-1'],
        analystAnnotations: [],
        relationships: [],
        kind: 'structured_record',
        summary: 'Observed process chain',
        tags: [],
      },
      {
        id: 'e-2',
        investigationId: 'inv-1',
        type: 'OBSERVATION',
        title: 'Maintenance macro approved by IT',
        source: 'change-record',
        timestamp: now + 1,
        collectedAt: now + 1,
        investigator: 'Historical Investigator',
        relatedEntityIds: [],
        content: 'Signed admin macro known to launch PowerShell during maintenance.',
        confidence: 0.8,
        provenance: { method: 'imported', sourceType: 'file' },
        hypothesisIds: ['hyp-1'],
        analystAnnotations: [],
        relationships: [],
        kind: 'note',
        summary: 'Potential benign explanation',
        tags: [],
      },
    ],
    entities: [],
    graph: { relationships: [] },
    timeline: [],
    openQuestions: [],
    aiTasks: [],
    humanTasks: [],
    decisions: [],
    conclusions: [],
    confidence: 0,
    activity: [],
  };
}

describe('ChallengerAgent', () => {
  it('reviews hypotheses for contradictory evidence and alternative explanations', () => {
    const agent = new ChallengerAgent();
    const result = agent.reviewInvestigation(makeInvestigation());

    expect(result.reviews).toHaveLength(1);
    expect(result.reviews[0].contradictoryEvidence.map((item) => item.id)).toEqual(['e-2']);
    expect(result.reviews[0].weakAssumptions.length).toBeGreaterThan(0);
    expect(result.reviews[0].alternativeExplanations[0]).toContain('Known legitimate behavior');
    expect(result.reviews[0].falsificationQuestions[0]).toContain('is false');
    expect(result.reviews[0].summary).toContain('contradictory evidence');
  });
});
