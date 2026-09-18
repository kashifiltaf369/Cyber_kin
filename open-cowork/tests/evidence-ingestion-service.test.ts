import { describe, expect, it } from 'vitest';
import {
  EvidenceIngestionService,
  validateWorkerResultShape,
} from '../src/main/investigation/evidence-ingestion-service';
import type { PlannedInvestigationTask } from '../src/main/investigation/parallel-investigation-engine';

function makeTask(kind: PlannedInvestigationTask['kind']): PlannedInvestigationTask {
  return {
    id: 'planned-1',
    title: 'Analyze identity activity',
    description: 'Review sign-ins',
    role: kind === 'analysis' ? 'Evidence Analyst' : 'Identity Investigator',
    kind,
    dependsOn: [],
    canRunConcurrently: true,
    mergeStrategy: 'append_evidence',
  };
}

describe('EvidenceIngestionService', () => {
  it('normalizes worker evidence with defaults and task provenance', () => {
    const service = new EvidenceIngestionService();
    const normalized = service.normalizeWorkerEvidence(
      {
        title: 'Suspicious sign-in',
        summary: 'Impossible travel observed',
        kind: 'log_excerpt',
        tags: ['identity'],
      },
      {
        investigationId: 'inv-1',
        plannedTask: makeTask('investigative'),
        runtimeTask: { id: 'runtime-1' },
        attempt: 2,
        workerSummary: 'Identity findings',
      }
    );

    expect(normalized.type).toBe('OBSERVATION');
    expect(normalized.investigator).toBe('Identity Investigator');
    expect(normalized.provenance.sourceType).toBe('task_result');
    expect(normalized.provenance.method).toBe('agent_observed');
    expect(normalized.provenance.details).toMatchObject({
      plannedTaskId: 'planned-1',
      runtimeTaskId: 'runtime-1',
      attempt: 2,
    });
    expect(normalized.supportingTaskId).toBe('runtime-1');
  });

  it('preserves explicit evidence typing and provenance when provided', () => {
    const service = new EvidenceIngestionService();
    const normalized = service.normalizeWorkerEvidence(
      {
        type: 'INFERENCE',
        title: 'Execution chain is unusual',
        summary: 'Word spawning PowerShell is uncommon here',
        kind: 'note',
        provenance: {
          method: 'derived_analysis',
          sourceType: 'task_result',
          sourceLabel: 'Analyst reasoning',
          collectedBy: 'Evidence Analyst',
        },
        confidence: 0.77,
        tags: ['analysis'],
      },
      {
        investigationId: 'inv-1',
        plannedTask: makeTask('analysis'),
        runtimeTask: { id: 'runtime-2' },
        attempt: 1,
        workerSummary: 'Analysis findings',
      }
    );

    expect(normalized.type).toBe('INFERENCE');
    expect(normalized.provenance.method).toBe('derived_analysis');
    expect(normalized.confidence).toBe(0.77);
  });
});

describe('validateWorkerResultShape', () => {
  it('accepts valid worker result objects', () => {
    const result = validateWorkerResultShape({
      summary: 'done',
      evidence: [{ title: 'obs', summary: 'sum', kind: 'note', type: 'OBSERVATION', tags: [] }],
      openQuestions: ['q'],
      notes: ['n'],
      hypothesisUpdates: [],
    });

    expect(result.ok).toBe(true);
    expect(result.issues).toHaveLength(0);
  });

  it('reports malformed worker results', () => {
    const result = validateWorkerResultShape({
      summary: '',
      evidence: [{ title: '', kind: 42, type: 'WRONG' }],
      openQuestions: 'not-array',
    });

    expect(result.ok).toBe(false);
    expect(result.issues.map((issue) => issue.path)).toEqual(
      expect.arrayContaining(['summary', 'evidence[0].title', 'evidence[0].kind', 'evidence[0].type', 'openQuestions'])
    );
  });
});
