import { describe, expect, it } from 'vitest';
import { InvestigationReasoningService } from '../src/main/investigation/investigation-reasoning-service';
import type { Investigation } from '../src/shared/cyber/investigation-types';

function makeInvestigation(): Investigation {
  const now = Date.now();
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
      knownLegitimateBehavior: [],
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
        status: 'OPEN',
        confidence: 0.5,
        createdAt: now,
        updatedAt: now,
      },
    ],
    evidence: [
      {
        id: 'e-1',
        investigationId: 'inv-1',
        type: 'OBSERVATION',
        title: 'PowerShell spawned by WINWORD.EXE',
        source: 'process-tree.json',
        timestamp: now,
        collectedAt: now,
        investigator: 'Endpoint Investigator',
        relatedEntityIds: [],
        content: 'PowerShell child of WINWORD.EXE',
        confidence: 0.9,
        provenance: { method: 'tool_output', sourceType: 'file' },
        supportingTaskId: 'task-1',
        hypothesisIds: [],
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
        title: 'Unsigned macro document',
        source: 'mail-attachment.eml',
        timestamp: now,
        collectedAt: now,
        investigator: 'Endpoint Investigator',
        relatedEntityIds: [],
        content: 'Attachment contains unsigned macro-enabled document',
        confidence: 0.8,
        provenance: { method: 'tool_output', sourceType: 'file' },
        supportingTaskId: 'task-2',
        hypothesisIds: [],
        analystAnnotations: [],
        relationships: [],
        kind: 'file',
        summary: 'Macro document observed',
        tags: [],
      },
    ],
    entities: [],
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

describe('InvestigationReasoningService', () => {
  it('summarizes supported/open hypotheses and linked/orphan evidence', () => {
    const service = new InvestigationReasoningService();
    const snapshot = service.summarize(makeInvestigation());

    expect(snapshot.openHypotheses).toHaveLength(1);
    expect(snapshot.supportedHypotheses).toHaveLength(0);
    expect(snapshot.orphanEvidence).toHaveLength(2);
    expect(snapshot.linkedEvidence).toHaveLength(0);
    expect(snapshot.latestConclusion).toBeNull();
  });

  it('synthesizes hypothesis assessments and derives a conclusion', () => {
    const service = new InvestigationReasoningService();
    const result = service.synthesize(makeInvestigation(), {
      assessments: [
        {
          hypothesisId: 'hyp-1',
          evidenceId: 'e-1',
          relationship: 'SUPPORTS',
          rationale: 'Process ancestry matches likely malicious execution',
        },
      ],
      conclusion: {
        hypothesisIds: ['hyp-1'],
        evidenceIds: ['e-1'],
      },
    });

    expect(result.hypotheses[0].status).toBe('SUPPORTED');
    expect(result.evidence[0].hypothesisIds).toContain('hyp-1');
    expect(result.conclusion?.derivedFromHypothesisIds).toEqual(['hyp-1']);
    expect(result.conclusion?.derivedFromEvidenceIds).toEqual(['e-1']);
    expect(result.snapshot.supportedHypotheses).toHaveLength(1);
    expect(result.snapshot.linkedEvidence).toHaveLength(1);
  });
});
