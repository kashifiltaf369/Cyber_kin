import { v4 as uuidv4 } from 'uuid';
import type { DatabaseInstance, InvestigationRow } from '../db/database';
import { log } from '../utils/logger';
import type {
  AddHumanContextInput,
  CreateInvestigationInput,
  EvidenceRelationshipType,
  HumanCapabilityContext,
  HumanConstraint,
  HumanNote,
  HumanPriority,
  Investigation,
  InvestigationConclusion,
  InvestigationDecision,
  InvestigationDirection,
  InvestigationEntity,
  InvestigationEvent,
  InvestigationEvidence,
  InvestigationEvidenceAnnotation,
  InvestigationEvidenceGraph,
  InvestigationGraphRelationship,
  InvestigationGraphRelationshipType,
  InvestigationHypothesis,
  InvestigationStatus,
  InvestigationTask,
  InvestigationTimelineEntry,
  UpdateInvestigationInput,
} from '../../shared/cyber/investigation-types';
import type { ServerEvent } from '../../renderer/types';
import { HypothesisService } from './hypothesis-service';
import { ChallengerAgent } from './challenger-agent';
import { ConclusionService } from './conclusion-service';
import { InvestigationReasoningService } from './investigation-reasoning-service';
import { InvestigationGraphService } from './investigation-graph-service';
import { InvestigationReportService, type InvestigationReport } from './investigation-report-service';
import { renderInvestigationReportMarkdown } from './investigation-report-markdown';

function clampConfidence(value: number | undefined): number {
  if (typeof value !== 'number' || Number.isNaN(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

function toTimelineEntry(event: InvestigationEvent): InvestigationTimelineEntry {
  return {
    id: event.id,
    summary: event.summary,
    occurredAt: event.createdAt,
    eventType: event.type,
  };
}

function defaultHumanCapabilityContext(
  riskTolerance: HumanCapabilityContext['riskTolerance'] = 'MEDIUM'
): HumanCapabilityContext {
  return {
    environmentalKnowledge: [],
    priorities: [],
    constraints: [],
    suspicions: [],
    knownLegitimateBehavior: [],
    knownAbnormalBehavior: [],
    riskTolerance,
    importantEntityIds: [],
    importantEntities: [],
    investigationDirections: [],
    notes: [],
  };
}

function appendStringUnique(values: string[], additions: string[]): string[] {
  const next = [...values];
  for (const item of additions.map((value) => value.trim()).filter(Boolean)) {
    if (!next.includes(item)) {
      next.push(item);
    }
  }
  return next;
}

function defaultInvestigationGraph(): InvestigationEvidenceGraph {
  return { relationships: [] };
}

function normalizeEvidence(
  investigationId: string,
  evidence: Partial<InvestigationEvidence> &
    Pick<InvestigationEvidence, 'id' | 'title' | 'kind'> &
    Partial<Pick<InvestigationEvidence, 'summary'>>
): InvestigationEvidence {
  const now = Date.now();
  const content = typeof evidence.content === 'string' && evidence.content.trim().length > 0
    ? evidence.content
    : evidence.summary || '';
  const summary = typeof evidence.summary === 'string' && evidence.summary.trim().length > 0
    ? evidence.summary
    : content;
  const source = typeof evidence.source === 'string' && evidence.source.trim().length > 0
    ? evidence.source
    : 'unknown';
  return {
    id: evidence.id,
    investigationId: evidence.investigationId || investigationId,
    type: evidence.type || 'OBSERVATION',
    title: evidence.title,
    source,
    timestamp: typeof evidence.timestamp === 'number' ? evidence.timestamp : evidence.collectedAt || now,
    collectedAt: evidence.collectedAt || now,
    investigator: evidence.investigator || 'agent',
    relatedEntityIds: Array.isArray(evidence.relatedEntityIds) ? evidence.relatedEntityIds : [],
    content,
    confidence: clampConfidence(evidence.confidence),
    provenance: {
      method: evidence.provenance?.method || 'agent_observed',
      sourceType: evidence.provenance?.sourceType || 'other',
      sourceId: evidence.provenance?.sourceId,
      sourceLabel: evidence.provenance?.sourceLabel,
      collectedBy: evidence.provenance?.collectedBy || evidence.investigator || 'agent',
      adapter: evidence.provenance?.adapter,
      capability: evidence.provenance?.capability,
      details: evidence.provenance?.details,
    },
    supportingTaskId: evidence.supportingTaskId,
    hypothesisIds: Array.isArray(evidence.hypothesisIds) ? evidence.hypothesisIds : [],
    analystAnnotations: Array.isArray(evidence.analystAnnotations) ? evidence.analystAnnotations : [],
    relationships: Array.isArray(evidence.relationships) ? evidence.relationships : [],
    kind: evidence.kind,
    summary,
    tags: Array.isArray(evidence.tags) ? evidence.tags : [],
  };
}

export class InvestigationService {
  private readonly hypothesisService: HypothesisService;
  private readonly conclusionService: ConclusionService;
  private readonly reasoningService: InvestigationReasoningService;
  private readonly graphService: InvestigationGraphService;
  private readonly challengerAgent: ChallengerAgent;
  private readonly reportService: InvestigationReportService;

  constructor(
    private readonly db: DatabaseInstance,
    private readonly sendToRenderer?: (event: ServerEvent) => void,
    hypothesisService = new HypothesisService(),
    conclusionService = new ConclusionService(),
    reasoningService = new InvestigationReasoningService(hypothesisService, conclusionService),
    graphService = new InvestigationGraphService(),
    challengerAgent = new ChallengerAgent(hypothesisService),
    reportService = new InvestigationReportService(new ChallengerAgent(new HypothesisService()))
  ) {
    this.hypothesisService = hypothesisService;
    this.conclusionService = conclusionService;
    this.reasoningService = reasoningService;
    this.graphService = graphService;
    this.challengerAgent = challengerAgent;
    this.reportService = reportService;
  }

  list(): Investigation[] {
    return this.db.investigations
      .getAll()
      .map((row) => this.inflate(row))
      .sort((a, b) => {
        if (b.updatedAt !== a.updatedAt) return b.updatedAt - a.updatedAt;
        if (b.createdAt !== a.createdAt) return b.createdAt - a.createdAt;
        return b.id.localeCompare(a.id);
      });
  }

  get(id: string): Investigation | null {
    const row = this.db.investigations.get(id);
    return row ? this.inflate(row) : null;
  }

  create(input: CreateInvestigationInput): Investigation {
    const now = Date.now();
    const id = uuidv4();
    const hypotheses: InvestigationHypothesis[] = (input.hypotheses || []).map((item) =>
      this.hypothesisService.create(item, now)
    );
    const openQuestions = (input.openQuestions || []).map((item) => item.trim()).filter(Boolean);

    const row = {
      id,
      title: input.title.trim(),
      objective: input.objective.trim(),
      status: 'CREATED' as InvestigationStatus,
      created_at: now,
      updated_at: now,
      human_context: (input.humanContext || '').trim(),
      human_capability_context: JSON.stringify(defaultHumanCapabilityContext(input.riskTolerance)),
      hypotheses: JSON.stringify(hypotheses),
      evidence: JSON.stringify([] satisfies InvestigationEvidence[]),
      entities: JSON.stringify([] satisfies InvestigationEntity[]),
      graph: JSON.stringify(defaultInvestigationGraph()),
      timeline: JSON.stringify([] satisfies InvestigationTimelineEntry[]),
      open_questions: JSON.stringify(openQuestions),
      ai_tasks: JSON.stringify([] satisfies InvestigationTask[]),
      human_tasks: JSON.stringify([] satisfies InvestigationTask[]),
      decisions: JSON.stringify([] satisfies InvestigationDecision[]),
      conclusions: JSON.stringify([] satisfies InvestigationConclusion[]),
      confidence: 0,
    };

    this.db.investigations.create(row);

    const created = this.get(id)!;
    this.recordEvent(id, 'INVESTIGATION_CREATED', 'system', `Investigation created: ${created.title}`, {
      title: created.title,
      objective: created.objective,
    });
    for (const hypothesis of hypotheses) {
      this.recordEvent(id, 'HYPOTHESIS_CREATED', 'human', `Hypothesis created: ${hypothesis.title}`, {
        hypothesisId: hypothesis.id,
      });
    }
    for (const question of openQuestions) {
      this.recordEvent(id, 'OPEN_QUESTION_ADDED', 'human', `Open question added: ${question}`, {
        question,
      });
    }
    return this.get(id)!;
  }

  linkSession(investigationId: string, sessionId: string, role: 'lead' | 'worker' | 'critic' = 'lead'): void {
    this.require(investigationId);
    this.db.investigationSessionLinks.link(investigationId, sessionId, role);
  }

  getInvestigationIdBySessionId(sessionId: string): string | null {
    return this.db.investigationSessionLinks.getInvestigationIdBySessionId(sessionId);
  }

  open(id: string): Investigation {
    const investigation = this.require(id);
    this.recordEvent(id, 'INVESTIGATION_OPENED', 'human', `Investigation opened: ${investigation.title}`);
    return this.require(id);
  }

  resume(id: string): Investigation {
    const investigation = this.require(id);
    const nextStatus: InvestigationStatus =
      investigation.status === 'ARCHIVED' ? 'ARCHIVED' : 'INVESTIGATING';
    if (nextStatus !== investigation.status) {
      this.update(id, { status: nextStatus });
    }
    this.recordEvent(id, 'INVESTIGATION_RESUMED', 'human', `Investigation resumed: ${investigation.title}`);
    return this.require(id);
  }

  archive(id: string): Investigation {
    const updated = this.update(id, { status: 'ARCHIVED' });
    this.recordEvent(id, 'INVESTIGATION_ARCHIVED', 'human', `Investigation archived: ${updated.title}`);
    return this.require(id);
  }

  update(id: string, updates: UpdateInvestigationInput): Investigation {
    const existing = this.require(id);
    const mapped: Record<string, unknown> = {};
    if (updates.title !== undefined) mapped.title = updates.title.trim();
    if (updates.objective !== undefined) mapped.objective = updates.objective.trim();
    if (updates.humanContext !== undefined) mapped.human_context = updates.humanContext.trim();
    if (updates.status !== undefined) mapped.status = updates.status;
    if (updates.confidence !== undefined) mapped.confidence = clampConfidence(updates.confidence);
    this.db.investigations.update(id, mapped);
    const updated = this.require(id);
    if (updates.status && updates.status !== existing.status) {
      this.recordEvent(
        id,
        'INVESTIGATION_STATUS_CHANGED',
        'system',
        `Investigation status changed from ${existing.status} to ${updates.status}`,
        { from: existing.status, to: updates.status }
      );
    }
    return updated;
  }

  addHumanInput(id: string, text: string): Investigation {
    const investigation = this.require(id);
    const nextContext = [investigation.humanContext, text.trim()].filter(Boolean).join('\n\n');
    const updated = this.update(id, { humanContext: nextContext });
    this.recordEvent(id, 'HUMAN_INPUT_ADDED', 'human', 'Human input added', { text });
    return updated;
  }

  addHumanContext(id: string, input: AddHumanContextInput): Investigation {
    const investigation = this.require(id);
    const current = investigation.humanCapabilityContext;
    const now = Date.now();
    const importantEntities = [
      ...current.importantEntities,
      ...(input.importantEntities || []).map((entity) => ({
        id: uuidv4(),
        name: entity.name,
        type: entity.type,
        summary: entity.summary,
        createdAt: now,
      })),
    ];
    const next: HumanCapabilityContext = {
      ...current,
      environmentalKnowledge: appendStringUnique(
        current.environmentalKnowledge,
        input.environmentalKnowledge || []
      ),
      suspicions: [
        ...current.suspicions,
        ...(input.suspicions || []).map((value) => ({ id: uuidv4(), value: value.trim(), createdAt: now })),
      ].filter((item) => item.value),
      knownLegitimateBehavior: [
        ...current.knownLegitimateBehavior,
        ...(input.knownLegitimateBehavior || []).map((value) => ({ id: uuidv4(), value: value.trim(), createdAt: now })),
      ].filter((item) => item.value),
      knownAbnormalBehavior: [
        ...current.knownAbnormalBehavior,
        ...(input.knownAbnormalBehavior || []).map((value) => ({ id: uuidv4(), value: value.trim(), createdAt: now })),
      ].filter((item) => item.value),
      notes: [
        ...current.notes,
        ...(input.notes || []).map((value) => ({ id: uuidv4(), value: value.trim(), createdAt: now })),
      ].filter((item) => item.value),
      riskTolerance: input.riskTolerance || current.riskTolerance,
      importantEntities,
      importantEntityIds: importantEntities.map((entity) => entity.id),
    };
    this.db.investigations.update(id, { human_capability_context: JSON.stringify(next) });
    this.recordEvent(id, 'HUMAN_CONTEXT_ADDED', 'human', 'Human context added', {
      environmentalKnowledge: input.environmentalKnowledge || [],
      suspicions: input.suspicions || [],
      notes: input.notes || [],
      riskTolerance: input.riskTolerance,
      importantEntities: (input.importantEntities || []).map((item) => item.name),
    });
    return this.require(id);
  }

  getHumanContext(id: string): HumanCapabilityContext {
    return this.require(id).humanCapabilityContext;
  }

  addConstraint(id: string, value: string): Investigation {
    const investigation = this.require(id);
    const current = investigation.humanCapabilityContext;
    const entry: HumanConstraint = { id: uuidv4(), value: value.trim(), createdAt: Date.now() };
    this.db.investigations.update(id, {
      human_capability_context: JSON.stringify({
        ...current,
        constraints: [...current.constraints, entry],
      }),
    });
    this.recordEvent(id, 'CONSTRAINT_ADDED', 'human', `Constraint added: ${entry.value}`, {
      constraintId: entry.id,
      value: entry.value,
    });
    return this.require(id);
  }

  addPriority(id: string, value: string): Investigation {
    const investigation = this.require(id);
    const current = investigation.humanCapabilityContext;
    const entry: HumanPriority = { id: uuidv4(), value: value.trim(), createdAt: Date.now() };
    this.db.investigations.update(id, {
      human_capability_context: JSON.stringify({
        ...current,
        priorities: [...current.priorities, entry],
      }),
    });
    this.recordEvent(id, 'PRIORITY_ADDED', 'human', `Priority added: ${entry.value}`, {
      priorityId: entry.id,
      value: entry.value,
    });
    return this.require(id);
  }

  addEvidence(
    id: string,
    input: Omit<InvestigationEvidence, 'id' | 'investigationId' | 'collectedAt' | 'relationships' | 'analystAnnotations'> & {
      collectedAt?: number;
      relationships?: InvestigationEvidence['relationships'];
      analystAnnotations?: InvestigationEvidence['analystAnnotations'];
    }
  ): Investigation {
    const investigation = this.require(id);
    const evidence = normalizeEvidence(id, {
      ...input,
      id: uuidv4(),
      relationships: input.relationships || [],
      analystAnnotations: input.analystAnnotations || [],
    });
    const next = [...investigation.evidence.map((item) => normalizeEvidence(id, item)), evidence];
    this.db.investigations.update(id, { evidence: JSON.stringify(next) });
    this.recordEvent(id, 'EVIDENCE_ADDED', 'agent', `Evidence added: ${evidence.title}`, {
      evidenceId: evidence.id,
      evidenceType: evidence.type,
      kind: evidence.kind,
      source: evidence.source,
      provenance: evidence.provenance,
      supportingTaskId: evidence.supportingTaskId,
    });
    return this.require(id);
  }

  addHypothesis(
    id: string,
    input: {
      title: string;
      statement: string;
      confidence?: number;
      assumptions?: string[];
      unresolvedQuestions?: string[];
      createdBy?: 'human' | 'agent' | 'system';
    }
  ): Investigation {
    const investigation = this.require(id);
    const hypothesis = this.hypothesisService.create(input);
    this.db.investigations.update(id, {
      hypotheses: JSON.stringify([...investigation.hypotheses.map((item) => this.hypothesisService.normalize(item)), hypothesis]),
    });
    this.recordEvent(id, 'HYPOTHESIS_CREATED', input.createdBy || 'human', `Hypothesis created: ${hypothesis.title}`, {
      hypothesisId: hypothesis.id,
      confidence: hypothesis.confidence,
      confidenceAssessment: hypothesis.confidenceAssessment,
      assumptions: hypothesis.assumptions,
      unresolvedQuestions: hypothesis.unresolvedQuestions,
    });
    return this.require(id);
  }

  updateHypothesis(
    id: string,
    hypothesisId: string,
    updates: Partial<
      Pick<InvestigationHypothesis, 'title' | 'statement' | 'status' | 'confidence' | 'assumptions' | 'unresolvedQuestions'>
    >
  ): Investigation {
    const investigation = this.require(id);
    const next = this.hypothesisService.update(investigation.hypotheses, hypothesisId, updates);
    this.db.investigations.update(id, { hypotheses: JSON.stringify(next) });
    const updatedHypothesis = next.find((item) => item.id === hypothesisId) || null;
    this.recordEvent(id, 'HYPOTHESIS_UPDATED', 'agent', `Hypothesis updated: ${hypothesisId}`, {
      hypothesisId,
      updates,
      confidence: updatedHypothesis?.confidence,
      confidenceAssessment: updatedHypothesis?.confidenceAssessment,
      supportingEvidenceIds: updatedHypothesis?.supportingEvidenceIds,
      contradictingEvidenceIds: updatedHypothesis?.contradictingEvidenceIds,
    });
    return this.require(id);
  }

  addOpenQuestion(id: string, question: string): Investigation {
    const investigation = this.require(id);
    const next = [...investigation.openQuestions, question.trim()].filter(Boolean);
    this.db.investigations.update(id, { open_questions: JSON.stringify(next) });
    this.recordEvent(id, 'OPEN_QUESTION_ADDED', 'agent', `Open question added: ${question.trim()}`, {
      question,
    });
    return this.require(id);
  }

  addTask(
    id: string,
    input: Omit<InvestigationTask, 'id' | 'createdAt' | 'updatedAt' | 'status'> & { status?: InvestigationTask['status'] }
  ): Investigation {
    const investigation = this.require(id);
    const now = Date.now();
    const task: InvestigationTask = {
      id: uuidv4(),
      title: input.title,
      description: input.description,
      type: input.type,
      status: input.status || 'CREATED',
      createdAt: now,
      updatedAt: now,
      owner: input.owner,
      priority: input.priority,
    };
    const targetKey = task.type === 'AI' ? 'ai_tasks' : 'human_tasks';
    const currentTasks = task.type === 'AI' ? investigation.aiTasks : investigation.humanTasks;
    this.db.investigations.update(id, { [targetKey]: JSON.stringify([...currentTasks, task]) });
    this.recordEvent(id, 'TASK_CREATED', task.type === 'AI' ? 'agent' : 'human', `Task created: ${task.title}`, {
      taskId: task.id,
      taskType: task.type,
    });
    if (task.status === 'STARTED') {
      this.recordEvent(id, 'TASK_STARTED', task.type === 'AI' ? 'agent' : 'human', `Task started: ${task.title}`, {
        taskId: task.id,
      });
    }
    if (task.status === 'COMPLETED') {
      this.recordEvent(
        id,
        'TASK_COMPLETED',
        task.type === 'AI' ? 'agent' : 'human',
        `Task completed: ${task.title}`,
        { taskId: task.id }
      );
    }
    return this.require(id);
  }

  updateTask(
    id: string,
    taskId: string,
    updates: Partial<Pick<InvestigationTask, 'title' | 'description' | 'status' | 'owner' | 'priority'>>
  ): Investigation {
    const investigation = this.require(id);
    const updateTasks = (tasks: InvestigationTask[]) =>
      tasks.map((task) =>
        task.id === taskId
          ? {
              ...task,
              ...(updates.title !== undefined ? { title: updates.title } : {}),
              ...(updates.description !== undefined ? { description: updates.description } : {}),
              ...(updates.status !== undefined ? { status: updates.status } : {}),
              ...(updates.owner !== undefined ? { owner: updates.owner } : {}),
              ...(updates.priority !== undefined ? { priority: updates.priority } : {}),
              updatedAt: Date.now(),
            }
          : task
      );
    this.db.investigations.update(id, {
      ai_tasks: JSON.stringify(updateTasks(investigation.aiTasks)),
      human_tasks: JSON.stringify(updateTasks(investigation.humanTasks)),
    });
    this.recordEvent(id, 'TASK_UPDATED', 'system', `Task updated: ${taskId}`, { taskId, updates });
    if (updates.status === 'STARTED') {
      this.recordEvent(id, 'TASK_STARTED', 'system', `Task started: ${taskId}`, { taskId });
    }
    if (updates.status === 'PAUSED') {
      this.recordEvent(id, 'TASK_PAUSED', 'system', `Task paused: ${taskId}`, { taskId });
    }
    if (updates.status === 'COMPLETED') {
      this.recordEvent(id, 'TASK_COMPLETED', 'system', `Task completed: ${taskId}`, { taskId });
    }
    return this.require(id);
  }

  ignoreFinding(id: string, evidenceId: string, rationale: string): Investigation {
    const investigation = this.annotateEvidence(id, evidenceId, {
      author: 'human',
      note: `Ignored finding: ${rationale.trim()}`,
    });
    this.recordEvent(id, 'TASK_IGNORED', 'human', `Finding ignored: ${evidenceId}`, {
      evidenceId,
      rationale: rationale.trim(),
    });
    return investigation;
  }

  addDecision(id: string, input: { summary: string; rationale?: string }): Investigation {
    const investigation = this.require(id);
    const decision: InvestigationDecision = {
      id: uuidv4(),
      summary: input.summary,
      rationale: input.rationale,
      createdAt: Date.now(),
    };
    this.db.investigations.update(id, {
      decisions: JSON.stringify([...investigation.decisions, decision]),
    });
    this.recordEvent(id, 'DECISION_ADDED', 'human', `Decision added: ${decision.summary}`, {
      decisionId: decision.id,
    });
    return this.require(id);
  }

  upsertConclusion(
    id: string,
    input: {
      summary: string;
      confidence?: number;
      rationale?: string;
      derivedFromHypothesisIds?: string[];
      derivedFromEvidenceIds?: string[];
    }
  ): Investigation {
    const investigation = this.require(id);
    const result = this.conclusionService.upsert(investigation.conclusions, input);
    this.db.investigations.update(id, {
      conclusions: JSON.stringify(result.conclusions),
      confidence: result.conclusion.confidence,
    });
    this.recordEvent(id, 'CONCLUSION_UPDATED', 'agent', 'Conclusion updated', {
      conclusionId: result.conclusion.id,
      confidence: result.conclusion.confidence,
      derivedFromHypothesisIds: result.conclusion.derivedFromHypothesisIds,
      derivedFromEvidenceIds: result.conclusion.derivedFromEvidenceIds,
    });
    return this.require(id);
  }

  redirectInvestigation(id: string, direction: string): Investigation {
    const investigation = this.require(id);
    const current = investigation.humanCapabilityContext;
    const entry: InvestigationDirection = {
      id: uuidv4(),
      value: direction.trim(),
      createdAt: Date.now(),
    };
    this.db.investigations.update(id, {
      human_capability_context: JSON.stringify({
        ...current,
        investigationDirections: [...current.investigationDirections, entry],
      }),
      status: 'REPLANNING',
    });
    this.recordEvent(id, 'AGENT_REDIRECTED', 'human', `Investigation redirected: ${entry.value}`, {
      directionId: entry.id,
      value: entry.value,
    });
    this.recordEvent(
      id,
      'INVESTIGATION_STATUS_CHANGED',
      'system',
      `Investigation status changed to REPLANNING`,
      { to: 'REPLANNING' }
    );
    return this.require(id);
  }

  addNote(id: string, value: string): Investigation {
    const investigation = this.require(id);
    const current = investigation.humanCapabilityContext;
    const entry: HumanNote = { id: uuidv4(), value: value.trim(), createdAt: Date.now() };
    this.db.investigations.update(id, {
      human_capability_context: JSON.stringify({
        ...current,
        notes: [...current.notes, entry],
      }),
    });
    this.recordEvent(id, 'NOTE_ADDED', 'human', `Note added: ${entry.value}`, {
      noteId: entry.id,
    });
    return this.require(id);
  }

  linkEvidence(
    id: string,
    sourceEvidenceId: string,
    relationship: {
      type: EvidenceRelationshipType;
      targetEvidenceId?: string;
      targetEntityId?: string;
      targetHypothesisId?: string;
      supportingTaskId?: string;
      rationale?: string;
      createdBy?: 'human' | 'agent' | 'system';
    }
  ): Investigation {
    const investigation = this.require(id);
    const evidence = investigation.evidence.map((item) => normalizeEvidence(id, item));
    const updated = evidence.map((item) =>
      item.id === sourceEvidenceId
        ? {
            ...item,
            relationships: [
              ...item.relationships,
              {
                id: uuidv4(),
                type: relationship.type,
                targetEvidenceId: relationship.targetEvidenceId,
                targetEntityId: relationship.targetEntityId,
                targetHypothesisId: relationship.targetHypothesisId,
                supportingTaskId: relationship.supportingTaskId,
                rationale: relationship.rationale,
                createdAt: Date.now(),
                createdBy: relationship.createdBy || 'agent',
              },
            ],
          }
        : item
    );
    this.db.investigations.update(id, { evidence: JSON.stringify(updated) });
    this.recordEvent(id, 'EVIDENCE_LINKED', relationship.createdBy || 'agent', `Evidence linked: ${sourceEvidenceId}`, {
      sourceEvidenceId,
      relationshipType: relationship.type,
      targetEvidenceId: relationship.targetEvidenceId,
      targetEntityId: relationship.targetEntityId,
      targetHypothesisId: relationship.targetHypothesisId,
      supportingTaskId: relationship.supportingTaskId,
    });
    return this.require(id);
  }

  annotateEvidence(
    id: string,
    evidenceId: string,
    input: { note: string; author?: InvestigationEvidenceAnnotation['author'] }
  ): Investigation {
    const investigation = this.require(id);
    const evidence = investigation.evidence.map((item) => normalizeEvidence(id, item));
    const author = input.author || 'human';
    const updated = evidence.map((item) =>
      item.id === evidenceId
        ? {
            ...item,
            analystAnnotations: [
              ...item.analystAnnotations,
              {
                id: uuidv4(),
                author,
                note: input.note.trim(),
                createdAt: Date.now(),
              },
            ],
          }
        : item
    );
    this.db.investigations.update(id, { evidence: JSON.stringify(updated) });
    this.recordEvent(id, 'EVIDENCE_ANNOTATED', author, `Evidence annotated: ${evidenceId}`, {
      evidenceId,
      note: input.note.trim(),
    });
    return this.require(id);
  }

  getEvidenceForEntity(id: string, entityId: string): InvestigationEvidence[] {
    return this.require(id)
      .evidence.map((item) => normalizeEvidence(id, item))
      .filter(
        (item) =>
          item.relatedEntityIds.includes(entityId) ||
          item.relationships.some((relationship) => relationship.targetEntityId === entityId)
      );
  }

  getEvidenceForHypothesis(id: string, hypothesisId: string): InvestigationEvidence[] {
    return this.require(id)
      .evidence.map((item) => normalizeEvidence(id, item))
      .filter(
        (item) =>
          item.hypothesisIds.includes(hypothesisId) ||
          item.relationships.some((relationship) => relationship.targetHypothesisId === hypothesisId)
      );
  }

  getEvidenceTimeline(id: string): InvestigationEvidence[] {
    return this.require(id)
      .evidence.map((item) => normalizeEvidence(id, item))
      .sort((a, b) => a.timestamp - b.timestamp || a.collectedAt - b.collectedAt || a.id.localeCompare(b.id));
  }

  getLatestReplanRecommendation(id: string): InvestigationEvent | null {
    const activity = this.require(id).activity;
    for (let index = activity.length - 1; index >= 0; index -= 1) {
      const event = activity[index];
      if (event.type === 'REPLAN_RECOMMENDED') {
        return event;
      }
    }
    return null;
  }

  getCyberAuditEvents(
    id: string,
    options: { mode?: 'recent' | 'denied' | 'high_risk'; limit?: number } = {}
  ): InvestigationEvent[] {
    const maxItems = Math.max(1, Math.min(options.limit || 10, 100));
    const auditEvents = this.require(id).activity
      .filter((event) => event.type === 'CYBER_ACTION_AUDITED')
      .sort((a, b) => b.createdAt - a.createdAt);

    const filtered = auditEvents.filter((event) => {
      const data = event.data || {};
      const actionCategory = String(data.actionCategory || '');
      const approvalState = String(data.approvalState || '');
      const result = String(((data.result as Record<string, unknown> | undefined)?.status) || '');

      switch (options.mode || 'recent') {
        case 'denied':
          return result === 'denied' || approvalState === 'REQUIRES_EXPLICIT_HUMAN_APPROVAL';
        case 'high_risk':
          return actionCategory === 'HIGH_RISK_ACTION' || actionCategory === 'DESTRUCTIVE_ACTION';
        case 'recent':
        default:
          return true;
      }
    });

    return filtered.slice(0, maxItems);
  }

  summarizeCyberAuditEvents(id: string, limit = 10): {
    investigationId: string;
    totalAuditEvents: number;
    deniedCount: number;
    explicitApprovalRequiredCount: number;
    highRiskCount: number;
    recent: InvestigationEvent[];
  } {
    const investigation = this.require(id);
    const auditEvents = investigation.activity.filter((event) => event.type === 'CYBER_ACTION_AUDITED');
    return {
      investigationId: id,
      totalAuditEvents: auditEvents.length,
      deniedCount: auditEvents.filter(
        (event) => String(((event.data?.result as Record<string, unknown> | undefined)?.status) || '') === 'denied'
      ).length,
      explicitApprovalRequiredCount: auditEvents.filter(
        (event) => String(event.data?.approvalState || '') === 'REQUIRES_EXPLICIT_HUMAN_APPROVAL'
      ).length,
      highRiskCount: auditEvents.filter((event) => {
        const category = String(event.data?.actionCategory || '');
        return category === 'HIGH_RISK_ACTION' || category === 'DESTRUCTIVE_ACTION';
      }).length,
      recent: this.getCyberAuditEvents(id, { mode: 'recent', limit }),
    };
  }

  addGraphRelationship(
    id: string,
    input: {
      type: InvestigationGraphRelationshipType;
      sourceEntityId: string;
      targetEntityId: string;
      source: string;
      timestamp?: number;
      confidence?: number;
      evidenceIds?: string[];
      supportingTaskId?: string;
      investigator?: string;
      direction?: InvestigationGraphRelationship['direction'];
      metadata?: Record<string, unknown>;
    }
  ): Investigation {
    const investigation = this.require(id);
    const result = this.graphService.addRelationship(investigation, input);
    this.db.investigations.update(id, { graph: JSON.stringify(result.graph) });
    this.recordEvent(id, 'GRAPH_RELATIONSHIP_ADDED', 'agent', `Graph relationship added: ${input.type}`, {
      relationshipId: result.relationship.id,
      relationshipType: result.relationship.type,
      sourceEntityId: result.relationship.sourceEntityId,
      targetEntityId: result.relationship.targetEntityId,
      evidenceIds: result.relationship.evidenceIds,
      supportingTaskId: result.relationship.supportingTaskId,
    });
    return this.require(id);
  }

  getGraph(id: string): InvestigationEvidenceGraph {
    return this.graphService.getGraph(this.require(id));
  }

  getGraphRelationshipsForEntity(
    id: string,
    query: {
      entityId: string;
      relationshipTypes?: InvestigationGraphRelationshipType[];
      direction?: 'outbound' | 'inbound' | 'both';
      startTime?: number;
      endTime?: number;
    }
  ): InvestigationGraphRelationship[] {
    return this.graphService.getRelationshipsForEntity(this.require(id), query);
  }

  findConnectedEntities(
    id: string,
    query: {
      entityId: string;
      relationshipTypes?: InvestigationGraphRelationshipType[];
      direction?: 'outbound' | 'inbound' | 'both';
      startTime?: number;
      endTime?: number;
    }
  ): Array<{ entity: InvestigationEntity; relationships: InvestigationGraphRelationship[] }> {
    return this.graphService.findConnectedEntities(this.require(id), query);
  }

  findEntitiesConnectedWithinTimeWindow(
    id: string,
    query: {
      entityId: string;
      withinMs: number;
      relationshipTypes?: InvestigationGraphRelationshipType[];
      direction?: 'outbound' | 'inbound' | 'both';
      anchorTimestamp?: number;
    }
  ): Array<{ entity: InvestigationEntity; relationships: InvestigationGraphRelationship[] }> {
    return this.graphService.findEntitiesConnectedWithinTimeWindow(this.require(id), query);
  }

  getEvidenceForGraphRelationship(id: string, relationshipId: string): InvestigationEvidence[] {
    return this.graphService.getEvidenceForRelationship(this.require(id), relationshipId);
  }

  updateHypothesisConfidence(id: string, hypothesisId: string, confidence: number): Investigation {
    const investigation = this.require(id);
    const next = this.hypothesisService.updateConfidence(investigation.hypotheses, hypothesisId, confidence);
    this.db.investigations.update(id, { hypotheses: JSON.stringify(next) });
    const updatedHypothesis = next.find((item) => item.id === hypothesisId) || null;
    this.recordEvent(id, 'HYPOTHESIS_UPDATED', 'agent', `Hypothesis confidence updated: ${hypothesisId}`, {
      hypothesisId,
      confidence: updatedHypothesis?.confidence,
      confidenceAssessment: updatedHypothesis?.confidenceAssessment,
      note: 'Confidence is an assessment, not an assertion of truth.',
    });
    return this.require(id);
  }

  addSupportingEvidence(id: string, hypothesisId: string, evidenceId: string, rationale?: string, actor?: 'human' | 'agent' | 'system'): Investigation {
    return this.applyEvidenceToHypothesis(id, {
      hypothesisId,
      evidenceId,
      relationship: 'SUPPORTS',
      rationale,
      actor,
    });
  }

  addContradictingEvidence(id: string, hypothesisId: string, evidenceId: string, rationale?: string, actor?: 'human' | 'agent' | 'system'): Investigation {
    return this.applyEvidenceToHypothesis(id, {
      hypothesisId,
      evidenceId,
      relationship: 'WEAKENS',
      rationale,
      actor,
    });
  }

  rejectHypothesis(id: string, hypothesisId: string): Investigation {
    const investigation = this.require(id);
    const next = this.hypothesisService.reject(investigation.hypotheses, hypothesisId);
    this.db.investigations.update(id, { hypotheses: JSON.stringify(next) });
    const updatedHypothesis = next.find((item) => item.id === hypothesisId) || null;
    this.recordEvent(id, 'HYPOTHESIS_UPDATED', 'agent', `Hypothesis rejected: ${hypothesisId}`, {
      hypothesisId,
      status: updatedHypothesis?.status,
      confidence: updatedHypothesis?.confidence,
      confidenceAssessment: updatedHypothesis?.confidenceAssessment,
    });
    return this.require(id);
  }

  promoteHypothesis(id: string, hypothesisId: string): Investigation {
    const investigation = this.require(id);
    const next = this.hypothesisService.promote(investigation.hypotheses, hypothesisId);
    this.db.investigations.update(id, { hypotheses: JSON.stringify(next) });
    const updatedHypothesis = next.find((item) => item.id === hypothesisId) || null;
    this.recordEvent(id, 'HYPOTHESIS_UPDATED', 'agent', `Hypothesis promoted: ${hypothesisId}`, {
      hypothesisId,
      status: updatedHypothesis?.status,
      confidence: updatedHypothesis?.confidence,
      confidenceAssessment: updatedHypothesis?.confidenceAssessment,
    });
    return this.require(id);
  }

  compareHypotheses(id: string) {
    return this.hypothesisService.compare(this.require(id).hypotheses);
  }

  generateReport(id: string): InvestigationReport {
    const investigation = this.require(id);
    const report = this.reportService.buildReport(investigation);
    this.recordEvent(id, 'REPORT_GENERATED', 'agent', 'Investigation report generated', {
      reportConfidence: report.confidenceAssessment.overall,
      evidenceCount: report.evidence.length,
      hypothesisCount: report.hypotheses.length,
      conclusionPresent: Boolean(report.finalConclusion.conclusion),
    });
    return report;
  }

  renderReportMarkdown(id: string): string {
    const report = this.generateReport(id);
    return renderInvestigationReportMarkdown(report);
  }

  challengeHypotheses(id: string) {
    return this.challengerAgent.reviewInvestigation(this.require(id));
  }

  applyEvidenceToHypothesis(
    id: string,
    input: {
      hypothesisId: string;
      evidenceId: string;
      relationship: 'SUPPORTS' | 'WEAKENS';
      rationale?: string;
      actor?: 'human' | 'agent' | 'system';
    }
  ): Investigation {
    const investigation = this.require(id);
    const result = this.hypothesisService.applyEvidenceAssessment(investigation, input);
    this.db.investigations.update(id, {
      hypotheses: JSON.stringify(result.hypotheses),
      evidence: JSON.stringify(result.evidence),
    });
    this.recordEvent(id, 'HYPOTHESIS_UPDATED', input.actor || 'agent', `Hypothesis updated from evidence: ${input.hypothesisId}`, {
      hypothesisId: input.hypothesisId,
      evidenceId: input.evidenceId,
      relationship: input.relationship,
      rationale: input.rationale,
      confidence: result.hypothesis?.confidence,
      confidenceAssessment: result.hypothesis?.confidenceAssessment,
      status: result.hypothesis?.status,
      supportingEvidenceIds: result.hypothesis?.supportingEvidenceIds,
      contradictingEvidenceIds: result.hypothesis?.contradictingEvidenceIds,
    });
    this.recordEvent(id, 'EVIDENCE_LINKED', input.actor || 'agent', `Evidence linked to hypothesis: ${input.evidenceId}`, {
      sourceEvidenceId: input.evidenceId,
      relationshipType: input.relationship,
      targetHypothesisId: input.hypothesisId,
      rationale: input.rationale,
    });
    return this.require(id);
  }

  deriveConclusionFromState(
    id: string,
    input: {
      summary?: string;
      rationale?: string;
      hypothesisIds?: string[];
      evidenceIds?: string[];
    } = {}
  ): Investigation {
    const investigation = this.require(id);
    const result = this.conclusionService.deriveFromInvestigation(investigation, input);
    this.db.investigations.update(id, {
      conclusions: JSON.stringify(result.conclusions),
      confidence: result.conclusion.confidence,
    });
    this.recordEvent(id, 'CONCLUSION_UPDATED', 'agent', 'Conclusion derived from investigation state', {
      conclusionId: result.conclusion.id,
      confidence: result.conclusion.confidence,
      derivedFromHypothesisIds: result.conclusion.derivedFromHypothesisIds,
      derivedFromEvidenceIds: result.conclusion.derivedFromEvidenceIds,
    });
    return this.require(id);
  }

  synthesizeReasoning(
    id: string,
    input: {
      assessments?: Array<{
        hypothesisId: string;
        evidenceId: string;
        relationship: 'SUPPORTS' | 'WEAKENS';
        rationale?: string;
        actor?: 'human' | 'agent' | 'system';
      }>;
      conclusion?: {
        summary?: string;
        rationale?: string;
        hypothesisIds?: string[];
        evidenceIds?: string[];
      };
    } = {}
  ): Investigation {
    const investigation = this.require(id);
    const result = this.reasoningService.synthesize(investigation, input);
    this.db.investigations.update(id, {
      hypotheses: JSON.stringify(result.hypotheses),
      evidence: JSON.stringify(result.evidence),
      ...(result.conclusion
        ? {
            conclusions: JSON.stringify([
              result.conclusion,
              ...investigation.conclusions.filter((item) => item.id !== result.conclusion?.id),
            ]),
            confidence: result.conclusion.confidence,
          }
        : {}),
    });

    for (const assessment of input.assessments || []) {
      const updatedHypothesis = result.hypotheses.find((item) => item.id === assessment.hypothesisId) || null;
      this.recordEvent(id, 'HYPOTHESIS_UPDATED', assessment.actor || 'agent', `Hypothesis updated from reasoning: ${assessment.hypothesisId}`, {
        hypothesisId: assessment.hypothesisId,
        evidenceId: assessment.evidenceId,
        relationship: assessment.relationship,
        rationale: assessment.rationale,
        confidence: updatedHypothesis?.confidence,
        status: updatedHypothesis?.status,
      });
      this.recordEvent(id, 'EVIDENCE_LINKED', assessment.actor || 'agent', `Evidence linked during reasoning: ${assessment.evidenceId}`, {
        sourceEvidenceId: assessment.evidenceId,
        relationshipType: assessment.relationship,
        targetHypothesisId: assessment.hypothesisId,
        rationale: assessment.rationale,
      });
    }

    if (result.conclusion) {
      this.recordEvent(id, 'CONCLUSION_UPDATED', 'agent', 'Conclusion synthesized from reasoning', {
        conclusionId: result.conclusion.id,
        confidence: result.conclusion.confidence,
        derivedFromHypothesisIds: result.conclusion.derivedFromHypothesisIds,
        derivedFromEvidenceIds: result.conclusion.derivedFromEvidenceIds,
      });
    }

    return this.require(id);
  }

  addEntity(id: string, input: Omit<InvestigationEntity, 'id' | 'createdAt'>): Investigation {
    const investigation = this.require(id);
    const entity: InvestigationEntity = {
      id: uuidv4(),
      name: input.name,
      type: input.type,
      summary: input.summary,
      createdAt: Date.now(),
    };
    this.db.investigations.update(id, {
      entities: JSON.stringify([...investigation.entities, entity]),
    });
    this.recordEvent(id, 'ENTITY_ADDED', 'agent', `Entity added: ${entity.name}`, {
      entityId: entity.id,
      entityType: entity.type,
    });
    return this.require(id);
  }

  recordEvent(
    investigationId: string,
    type: InvestigationEvent['type'],
    actor: InvestigationEvent['actor'],
    summary: string,
    data?: Record<string, unknown>
  ): InvestigationEvent {
    this.require(investigationId);
    const event: InvestigationEvent = {
      id: uuidv4(),
      investigationId,
      type,
      createdAt: Date.now(),
      actor,
      summary,
      data,
    };
    this.db.investigationEvents.create({
      id: event.id,
      investigation_id: investigationId,
      type: event.type,
      actor: event.actor,
      summary: event.summary,
      data: JSON.stringify(event.data ?? {}),
      created_at: event.createdAt,
    });
    this.db.investigations.update(investigationId, {
      timeline: JSON.stringify([...this.require(investigationId).timeline, toTimelineEntry(event)]),
    });
    this.sendToRenderer?.({ type: 'investigation.event', payload: { investigationId, event } } as ServerEvent);
    log(`[Investigation] ${event.type} ${investigationId}: ${event.summary}`);
    return event;
  }

  private require(id: string): Investigation {
    const row = this.db.investigations.get(id);
    if (!row) {
      throw new Error(`Investigation not found: ${id}`);
    }
    return this.inflate(row);
  }

  private inflate(row: InvestigationRow): Investigation {
    const parse = <T>(value: string, fallback: T): T => {
      try {
        return JSON.parse(value) as T;
      } catch {
        return fallback;
      }
    };
    const events = this.db.investigationEvents.getByInvestigationId(row.id).map((eventRow) => ({
      id: eventRow.id,
      investigationId: eventRow.investigation_id,
      type: eventRow.type as InvestigationEvent['type'],
      createdAt: eventRow.created_at,
      actor: eventRow.actor as InvestigationEvent['actor'],
      summary: eventRow.summary,
      data: parse<Record<string, unknown>>(eventRow.data || '{}', {}),
    }));
    return {
      id: row.id,
      title: row.title,
      objective: row.objective,
      status: row.status as InvestigationStatus,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      humanContext: row.human_context,
      humanCapabilityContext: {
        ...defaultHumanCapabilityContext(),
        ...parse<Partial<HumanCapabilityContext>>(row.human_capability_context || '{}', {}),
      },
      hypotheses: parse<InvestigationHypothesis[]>(row.hypotheses, []).map((item) => this.hypothesisService.normalize(item)),
      evidence: parse<InvestigationEvidence[]>(row.evidence, []).map((item) => normalizeEvidence(row.id, item)),
      entities: parse(row.entities, []),
      graph: {
        ...defaultInvestigationGraph(),
        ...parse<Partial<InvestigationEvidenceGraph>>(row.graph || '{}', {}),
        relationships: parse<Partial<InvestigationEvidenceGraph>>(row.graph || '{}', {}).relationships || [],
      },
      timeline: parse(row.timeline, []),
      openQuestions: parse(row.open_questions, []),
      aiTasks: parse(row.ai_tasks, []),
      humanTasks: parse(row.human_tasks, []),
      decisions: parse(row.decisions, []),
      conclusions: parse(row.conclusions, []),
      confidence: typeof row.confidence === 'number' ? row.confidence : 0,
      activity: events,
    };
  }
}
