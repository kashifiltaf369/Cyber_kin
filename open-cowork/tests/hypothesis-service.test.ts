import { describe, expect, it } from 'vitest';
import { HypothesisService } from '../src/main/investigation/hypothesis-service';
import type { Investigation } from '../src/shared/cyber/investigation-types';

function makeInvestigation(): Investigation {
  const now = Date.now();
  return {
    id: 'inv-1',
    title: 'Case',
    objective: 'Obj',
    status: 'CREATED',
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
        confidenceAssessment: 'MEDIUM',
        supportingEvidenceIds: [],
        contradictingEvidenceIds: [],
        assumptions: ['Assume parent-child process relationship indicates compromise'],
        unresolvedQuestions: ['Was the document signed?'],
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
        title: 'PowerShell spawned by WINWORD.EXE',
        source: 'process-tree.json',
        timestamp: now,
        collectedAt: now,
        investigator: 'Endpoint Investigator',
        relatedEntityIds: [],
        content: 'PowerShell child of WINWORD.EXE',
        confidence: 0.9,
        provenance: {
          method: 'tool_output',
          sourceType: 'file',
        },
        supportingTaskId: 'task-1',
        hypothesisIds: [],
        analystAnnotations: [],
        relationships: [],
        kind: 'structured_record',
        summary: 'Observed process chain',
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

describe('HypothesisService', () => {
  it('creates and updates hypotheses', () => {
    const service = new HypothesisService();
    const created = service.create({
      title: 'Credential theft',
      statement: 'Account compromise occurred',
      confidence: 0.6,
    }, 100);

    expect(created.status).toBe('OPEN');
    expect(created.confidence).toBe(0.6);
    expect(created.confidenceAssessment).toBe('MEDIUM');

    const updated = service.update([created], created.id, {
      status: 'SUPPORTED',
      confidence: 0.8,
    }, 200);

    expect(updated[0].status).toBe('SUPPORTED');
    expect(updated[0].confidence).toBe(0.8);
    expect(updated[0].confidenceAssessment).toBe('HIGH');
    expect(updated[0].updatedAt).toBe(200);
  });

  it('applies supporting evidence to a hypothesis explicitly', () => {
    const service = new HypothesisService();
    const result = service.applyEvidenceAssessment(makeInvestigation(), {
      hypothesisId: 'hyp-1',
      evidenceId: 'e-1',
      relationship: 'SUPPORTS',
      rationale: 'Observed chain aligns with malicious document behavior',
    }, 300);

    expect(result.hypothesis?.status).toBe('SUPPORTED');
    expect(result.hypothesis?.confidence).toBe(0.65);
    expect(result.hypothesis?.confidenceAssessment).toBe('MEDIUM');
    expect(result.hypothesis?.supportingEvidenceIds).toContain('e-1');
    expect(result.evidence[0].hypothesisIds).toContain('hyp-1');
    expect(result.evidence[0].relationships.some((item) => item.type === 'SUPPORTS')).toBe(true);
  });

  it('applies weakening evidence to a hypothesis explicitly', () => {
    const service = new HypothesisService();
    const result = service.applyEvidenceAssessment(makeInvestigation(), {
      hypothesisId: 'hyp-1',
      evidenceId: 'e-1',
      relationship: 'WEAKENS',
      rationale: 'Observed behavior may be legitimate in context',
    }, 300);

    expect(result.hypothesis?.status).toBe('WEAKENED');
    expect(result.hypothesis?.confidence).toBe(0.35);
    expect(result.hypothesis?.confidenceAssessment).toBe('LOW');
    expect(result.hypothesis?.contradictingEvidenceIds).toContain('e-1');
    expect(result.evidence[0].relationships.some((item) => item.type === 'WEAKENS')).toBe(true);
  });

  it('compares competing hypotheses without treating confidence as absolute truth', () => {
    const service = new HypothesisService();
    const first = service.create({
      title: 'Credential theft',
      statement: 'Stolen credentials were used',
      confidence: 0.7,
      assumptions: ['Assume IP reputation implies malicious intent'],
      unresolvedQuestions: ['Was MFA challenged?'],
      createdBy: 'human',
    }, 100);
    const second = service.create({
      title: 'Administrative maintenance',
      statement: 'Observed behavior is part of routine admin maintenance',
      confidence: 0.55,
      assumptions: ['Known admin windows are still active'],
      unresolvedQuestions: [],
      createdBy: 'human',
    }, 100);

    const comparison = service.compare([
      {
        ...first,
        supportingEvidenceIds: ['e-1', 'e-2'],
        contradictingEvidenceIds: ['e-3'],
      },
      {
        ...second,
        supportingEvidenceIds: ['e-4'],
        contradictingEvidenceIds: [],
      },
    ]);

    expect(comparison.ranked).toHaveLength(2);
    expect(comparison.leadingHypothesisId).toBe(comparison.ranked[0].hypothesis.id);
    expect(comparison.ranked[0].hypothesis.confidenceAssessment).toMatch(/LOW|MEDIUM|HIGH/);
    expect(comparison.ranked[0].netSupportScore).not.toBe(comparison.ranked[0].hypothesis.confidence);
  });

  it('supports promotion and rejection of competing hypotheses', () => {
    const service = new HypothesisService();
    const created = service.create({ title: 'Credential theft', statement: 'Compromise occurred', confidence: 0.5 }, 100);

    const promoted = service.promote([created], created.id, 200);
    expect(promoted[0].status).toBe('PROMOTED');
    expect(promoted[0].confidence).toBeGreaterThanOrEqual(0.75);

    const rejected = service.reject(promoted, created.id, 300);
    expect(rejected[0].status).toBe('REJECTED');
    expect(rejected[0].confidenceAssessment).toBe('LOW');
  });
});
