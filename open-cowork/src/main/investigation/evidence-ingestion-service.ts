import type { InvestigationEvidence, InvestigationTask } from '../../shared/cyber/investigation-types';
import type {
  InvestigationWorkerResult,
  PlannedInvestigationTask,
} from './parallel-investigation-engine';

export interface EvidenceIngestionContext {
  investigationId: string;
  plannedTask: PlannedInvestigationTask;
  runtimeTask: Pick<InvestigationTask, 'id'>;
  attempt: number;
  workerSummary: string;
}

export interface WorkerResultValidationIssue {
  path: string;
  message: string;
}

export interface WorkerResultValidationResult {
  ok: boolean;
  issues: WorkerResultValidationIssue[];
}

export class EvidenceIngestionService {
  normalizeWorkerEvidence(
    evidence: NonNullable<InvestigationWorkerResult['evidence']>[number],
    context: EvidenceIngestionContext
  ): Omit<InvestigationEvidence, 'id' | 'investigationId' | 'collectedAt'> & {
    collectedAt?: number;
    relationships?: InvestigationEvidence['relationships'];
    analystAnnotations?: InvestigationEvidence['analystAnnotations'];
  } {
    return {
      type: evidence.type || inferEvidenceTypeFromTask(context.plannedTask.kind),
      title: evidence.title,
      source: evidence.source || `worker:${context.plannedTask.role}`,
      timestamp: evidence.timestamp || Date.now(),
      collectedAt: evidence.collectedAt,
      investigator: evidence.investigator || context.plannedTask.role,
      relatedEntityIds: Array.isArray(evidence.relatedEntityIds) ? evidence.relatedEntityIds : [],
      content: evidence.content || evidence.summary || context.workerSummary,
      confidence:
        typeof evidence.confidence === 'number'
          ? evidence.confidence
          : inferEvidenceConfidenceFromTask(context.plannedTask.kind),
      provenance: evidence.provenance || {
        method:
          context.plannedTask.kind === 'analysis' || context.plannedTask.kind === 'challenge'
            ? 'derived_analysis'
            : 'agent_observed',
        sourceType: 'task_result',
        sourceId: context.plannedTask.id,
        sourceLabel: context.plannedTask.title,
        collectedBy: context.plannedTask.role,
        details: {
          plannedTaskId: context.plannedTask.id,
          runtimeTaskId: context.runtimeTask.id,
          taskKind: context.plannedTask.kind,
          attempt: context.attempt,
        },
      },
      supportingTaskId: evidence.supportingTaskId || context.runtimeTask.id,
      hypothesisIds: Array.isArray(evidence.hypothesisIds) ? evidence.hypothesisIds : [],
      analystAnnotations: evidence.analystAnnotations || [],
      relationships: evidence.relationships || [],
      kind: evidence.kind,
      summary: evidence.summary || evidence.content || context.workerSummary,
      tags: Array.isArray(evidence.tags) ? evidence.tags : [],
    };
  }
}

export function validateWorkerResultShape(value: unknown): WorkerResultValidationResult {
  const issues: WorkerResultValidationIssue[] = [];
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {
      ok: false,
      issues: [{ path: '', message: 'worker result must be a JSON object' }],
    };
  }

  const record = value as Record<string, unknown>;
  if (typeof record.summary !== 'string' || record.summary.trim().length === 0) {
    issues.push({ path: 'summary', message: 'summary must be a non-empty string' });
  }

  if (record.evidence !== undefined) {
    if (!Array.isArray(record.evidence)) {
      issues.push({ path: 'evidence', message: 'evidence must be an array when provided' });
    } else {
      for (const [index, item] of record.evidence.entries()) {
        if (!item || typeof item !== 'object' || Array.isArray(item)) {
          issues.push({ path: `evidence[${index}]`, message: 'evidence item must be an object' });
          continue;
        }
        const evidence = item as Record<string, unknown>;
        if (typeof evidence.title !== 'string' || evidence.title.trim().length === 0) {
          issues.push({ path: `evidence[${index}].title`, message: 'title must be a non-empty string' });
        }
        if (typeof evidence.kind !== 'string' || evidence.kind.trim().length === 0) {
          issues.push({ path: `evidence[${index}].kind`, message: 'kind must be a non-empty string' });
        }
        if (evidence.type !== undefined && !['OBSERVATION', 'INFERENCE', 'HYPOTHESIS', 'CONCLUSION'].includes(String(evidence.type))) {
          issues.push({ path: `evidence[${index}].type`, message: 'type must be OBSERVATION, INFERENCE, HYPOTHESIS, or CONCLUSION' });
        }
      }
    }
  }

  if (record.openQuestions !== undefined && !Array.isArray(record.openQuestions)) {
    issues.push({ path: 'openQuestions', message: 'openQuestions must be an array when provided' });
  }
  if (record.notes !== undefined && !Array.isArray(record.notes)) {
    issues.push({ path: 'notes', message: 'notes must be an array when provided' });
  }
  if (record.hypothesisUpdates !== undefined && !Array.isArray(record.hypothesisUpdates)) {
    issues.push({ path: 'hypothesisUpdates', message: 'hypothesisUpdates must be an array when provided' });
  }

  return { ok: issues.length === 0, issues };
}

function inferEvidenceTypeFromTask(
  taskKind: PlannedInvestigationTask['kind']
): InvestigationEvidence['type'] {
  switch (taskKind) {
    case 'analysis':
      return 'INFERENCE';
    case 'challenge':
      return 'INFERENCE';
    case 'research':
      return 'INFERENCE';
    case 'investigative':
    default:
      return 'OBSERVATION';
  }
}

function inferEvidenceConfidenceFromTask(taskKind: PlannedInvestigationTask['kind']): number {
  switch (taskKind) {
    case 'analysis':
      return 0.7;
    case 'challenge':
      return 0.6;
    case 'research':
      return 0.65;
    case 'investigative':
    default:
      return 0.8;
  }
}
