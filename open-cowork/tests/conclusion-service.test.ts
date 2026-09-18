import { describe, expect, it } from 'vitest';
import { ConclusionService } from '../src/main/investigation/conclusion-service';
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
        status: 'SUPPORTED',
        confidence: 0.8,
        createdAt: now,
        updatedAt: now,
      },
      {
        id: 'hyp-2',
        title: 'Benign admin activity',
        statement: 'This may be routine admin automation',
        status: 'WEAKENED',
        confidence: 0.3,
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
        hypothesisIds: ['hyp-1'],
        analystAnnotations: [],
        relationships: [],
        kind: 'structured_record',
        summary: 'Observed process chain',
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

describe('ConclusionService', () => {
  it('upserts a conclusion with derivation metadata', () => {
    const service = new ConclusionService();
    const result = service.upsert([], {
      summary: 'Likely malicious execution',
      confidence: 0.78,
      rationale: 'Supported by process chain evidence',
      derivedFromHypothesisIds: ['hyp-1'],
      derivedFromEvidenceIds: ['e-1'],
    }, 100);

    expect(result.conclusion.summary).toBe('Likely malicious execution');
    expect(result.conclusion.confidence).toBe(0.78);
    expect(result.conclusion.derivedFromHypothesisIds).toEqual(['hyp-1']);
    expect(result.conclusion.derivedFromEvidenceIds).toEqual(['e-1']);
    expect(result.conclusion.createdAt).toBe(100);
  });

  it('derives a conclusion from supported hypotheses and linked evidence', () => {
    const service = new ConclusionService();
    const result = service.deriveFromInvestigation(makeInvestigation(), {}, 200);

    expect(result.conclusion.summary).toContain('Malicious document execution');
    expect(result.conclusion.confidence).toBeGreaterThan(0.8);
    expect(result.conclusion.derivedFromHypothesisIds).toEqual(['hyp-1']);
    expect(result.conclusion.derivedFromEvidenceIds).toEqual(['e-1']);
  });

  it('uses explicit filters when deriving a conclusion', () => {
    const service = new ConclusionService();
    const result = service.deriveFromInvestigation(makeInvestigation(), {
      summary: 'Custom conclusion',
      hypothesisIds: ['hyp-1'],
      evidenceIds: ['e-1'],
    }, 300);

    expect(result.conclusion.summary).toBe('Custom conclusion');
    expect(result.conclusion.derivedFromHypothesisIds).toEqual(['hyp-1']);
    expect(result.conclusion.derivedFromEvidenceIds).toEqual(['e-1']);
  });
});
