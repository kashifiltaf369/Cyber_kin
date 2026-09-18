export type InvestigationStatus =
  | 'CREATED'
  | 'PLANNING'
  | 'INVESTIGATING'
  | 'WAITING_FOR_HUMAN'
  | 'REPLANNING'
  | 'CONCLUDED'
  | 'ARCHIVED';

export type InvestigationEventType =
  | 'INVESTIGATION_CREATED'
  | 'INVESTIGATION_OPENED'
  | 'INVESTIGATION_RESUMED'
  | 'INVESTIGATION_ARCHIVED'
  | 'INVESTIGATION_STATUS_CHANGED'
  | 'PLAN_CREATED'
  | 'TASK_CREATED'
  | 'TASK_STARTED'
  | 'TASK_COMPLETED'
  | 'TASK_UPDATED'
  | 'TASK_PAUSED'
  | 'TASK_RESUMED'
  | 'TASK_REPRIORITIZED'
  | 'TASK_IGNORED'
  | 'EVIDENCE_ADDED'
  | 'EVIDENCE_LINKED'
  | 'EVIDENCE_ANNOTATED'
  | 'GRAPH_RELATIONSHIP_ADDED'
  | 'REPLAN_RECOMMENDED'
  | 'HYPOTHESIS_CREATED'
  | 'HYPOTHESIS_UPDATED'
  | 'HUMAN_INPUT_ADDED'
  | 'HUMAN_CONTEXT_ADDED'
  | 'CONSTRAINT_ADDED'
  | 'PRIORITY_ADDED'
  | 'NOTE_ADDED'
  | 'AGENT_REDIRECTED'
  | 'CONCLUSION_UPDATED'
  | 'OPEN_QUESTION_ADDED'
  | 'DECISION_ADDED'
  | 'ENTITY_ADDED'
  | 'CYBER_ACTION_AUDITED'
  | 'REPORT_GENERATED'
  | 'OPERATIONAL_UPDATE';

export type HypothesisConfidenceAssessment = 'LOW' | 'MEDIUM' | 'HIGH';

export interface OperationalRationale {
  what: string;
  why: string;
  expectedValue: string;
  result?: string;
  next?: string;
}

export function isOperationalRationale(value: unknown): value is OperationalRationale {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as unknown as Record<string, unknown>;
  return typeof candidate.what === 'string'
    && typeof candidate.why === 'string'
    && typeof candidate.expectedValue === 'string'
    && (candidate.result === undefined || typeof candidate.result === 'string')
    && (candidate.next === undefined || typeof candidate.next === 'string');
}

export function toOperationalRationale(value: unknown): OperationalRationale | null {
  // isOperationalRationale has already verified every field's type; the cast
  // only recovers the checked shape for property access.
  if (!isOperationalRationale(value)) return null;
  const candidate = value as unknown as {
    what: string;
    why: string;
    expectedValue: string;
    result?: string;
    next?: string;
  };
  return {
    what: candidate.what,
    why: candidate.why,
    expectedValue: candidate.expectedValue,
    result: candidate.result,
    next: candidate.next,
  };
}

export interface InvestigationHypothesis {
  id: string;
  title: string;
  statement: string;
  status: 'OPEN' | 'SUPPORTED' | 'WEAKENED' | 'REJECTED' | 'PROMOTED';
  confidence: number;
  confidenceAssessment: HypothesisConfidenceAssessment;
  supportingEvidenceIds: string[];
  contradictingEvidenceIds: string[];
  assumptions: string[];
  unresolvedQuestions: string[];
  createdBy: 'human' | 'agent' | 'system';
  createdAt: number;
  updatedAt: number;
}

export type InvestigationEvidenceKind =
  | 'file'
  | 'log_excerpt'
  | 'url'
  | 'command_output'
  | 'api_result'
  | 'note'
  | 'image'
  | 'structured_record'
  | 'other';

export type InvestigationFindingType = 'OBSERVATION' | 'INFERENCE' | 'HYPOTHESIS' | 'CONCLUSION';

export type EvidenceRelationshipType =
  | 'SUPPORTS'
  | 'WEAKENS'
  | 'DERIVED_FROM'
  | 'RELATED_TO'
  | 'DUPLICATE_OF'
  | 'ABOUT_ENTITY'
  | 'ABOUT_HYPOTHESIS'
  | 'PRODUCED_BY_TASK';

export interface InvestigationEvidenceAnnotation {
  id: string;
  author: 'human' | 'agent' | 'system';
  note: string;
  createdAt: number;
}

export interface InvestigationEvidenceProvenance {
  method: 'human_reported' | 'agent_observed' | 'tool_output' | 'derived_analysis' | 'imported';
  sourceType: 'session_message' | 'tool_execution' | 'file' | 'log' | 'api' | 'human_input' | 'task_result' | 'other';
  sourceId?: string;
  sourceLabel?: string;
  collectedBy?: string;
  adapter?: string;
  capability?: string;
  details?: Record<string, unknown>;
}

export interface InvestigationEvidenceRelationship {
  id: string;
  type: EvidenceRelationshipType;
  targetEvidenceId?: string;
  targetEntityId?: string;
  targetHypothesisId?: string;
  supportingTaskId?: string;
  createdAt: number;
  createdBy: 'human' | 'agent' | 'system';
  rationale?: string;
}

export interface InvestigationEvidence {
  id: string;
  investigationId: string;
  type: InvestigationFindingType;
  title: string;
  source: string;
  timestamp: number;
  collectedAt: number;
  investigator: string;
  relatedEntityIds: string[];
  content: string;
  confidence: number;
  provenance: InvestigationEvidenceProvenance;
  supportingTaskId?: string;
  hypothesisIds: string[];
  analystAnnotations: InvestigationEvidenceAnnotation[];
  relationships: InvestigationEvidenceRelationship[];
  kind: InvestigationEvidenceKind;
  summary: string;
  tags: string[];
}

export type InvestigationEntityType =
  | 'ip'
  | 'domain'
  | 'host'
  | 'user'
  | 'file'
  | 'process'
  | 'url'
  | 'hash'
  | 'account'
  | 'service'
  | 'alert'
  | 'event'
  | 'other';

export interface InvestigationEntity {
  id: string;
  name: string;
  type: InvestigationEntityType;
  summary?: string;
  createdAt: number;
}

export type InvestigationGraphRelationshipType =
  | 'EXECUTED'
  | 'CONNECTED_TO'
  | 'AUTHENTICATED_TO'
  | 'DOWNLOADED'
  | 'CREATED'
  | 'SPAWNED'
  | 'RESOLVED'
  | 'ACCESSED'
  | 'COMMUNICATED_WITH'
  | 'RELATED_TO';

export interface InvestigationGraphRelationship {
  id: string;
  type: InvestigationGraphRelationshipType;
  sourceEntityId: string;
  targetEntityId: string;
  source: string;
  timestamp: number;
  confidence: number;
  evidenceIds: string[];
  createdAt: number;
  supportingTaskId?: string;
  investigator?: string;
  direction?: 'OUTBOUND' | 'INBOUND' | 'LATERAL' | 'UNKNOWN';
  metadata?: Record<string, unknown>;
}

export interface InvestigationEvidenceGraph {
  relationships: InvestigationGraphRelationship[];
}

export interface InvestigationTimelineEntry {
  id: string;
  summary: string;
  occurredAt: number;
  eventType?: InvestigationEventType | string;
}

export interface InvestigationTask {
  id: string;
  title: string;
  description: string;
  type: 'AI' | 'HUMAN';
  status: 'CREATED' | 'STARTED' | 'PAUSED' | 'COMPLETED' | 'CANCELLED' | 'BLOCKED';
  createdAt: number;
  updatedAt: number;
  owner?: string;
  priority?: number;
  /** Identifier of the planned task this runtime task was created from (set by the parallel engine). */
  plannedTaskId?: string;
}

export interface InvestigationDecision {
  id: string;
  summary: string;
  rationale?: string;
  createdAt: number;
}

export interface HumanPriority {
  id: string;
  value: string;
  createdAt: number;
}

export interface HumanConstraint {
  id: string;
  value: string;
  createdAt: number;
}

export interface HumanSuspicion {
  id: string;
  value: string;
  createdAt: number;
}

export interface KnownBehaviorEntry {
  id: string;
  value: string;
  createdAt: number;
}

export interface InvestigationDirection {
  id: string;
  value: string;
  createdAt: number;
}

export interface HumanNote {
  id: string;
  value: string;
  createdAt: number;
}

export interface HumanCapabilityContext {
  environmentalKnowledge: string[];
  priorities: HumanPriority[];
  constraints: HumanConstraint[];
  suspicions: HumanSuspicion[];
  knownLegitimateBehavior: KnownBehaviorEntry[];
  knownAbnormalBehavior: KnownBehaviorEntry[];
  riskTolerance: 'LOW' | 'MEDIUM' | 'HIGH';
  importantEntityIds: string[];
  importantEntities: InvestigationEntity[];
  investigationDirections: InvestigationDirection[];
  notes: HumanNote[];
}

export interface InvestigationConclusion {
  id: string;
  summary: string;
  confidence: number;
  derivedFromHypothesisIds: string[];
  derivedFromEvidenceIds: string[];
  rationale?: string;
  createdAt: number;
  updatedAt: number;
}

export interface InvestigationEvent {
  id: string;
  investigationId: string;
  type: InvestigationEventType;
  createdAt: number;
  actor: 'human' | 'agent' | 'system';
  summary: string;
  data?: Record<string, unknown>;
}

export interface Investigation {
  id: string;
  title: string;
  objective: string;
  status: InvestigationStatus;
  createdAt: number;
  updatedAt: number;
  humanContext: string;
  humanCapabilityContext: HumanCapabilityContext;
  hypotheses: InvestigationHypothesis[];
  evidence: InvestigationEvidence[];
  entities: InvestigationEntity[];
  graph: InvestigationEvidenceGraph;
  timeline: InvestigationTimelineEntry[];
  openQuestions: string[];
  aiTasks: InvestigationTask[];
  humanTasks: InvestigationTask[];
  decisions: InvestigationDecision[];
  conclusions: InvestigationConclusion[];
  confidence: number;
  activity: InvestigationEvent[];
}

export interface CreateInvestigationInput {
  title: string;
  objective: string;
  humanContext?: string;
  riskTolerance?: HumanCapabilityContext['riskTolerance'];
  hypotheses?: Array<{
    title: string;
    statement: string;
    confidence?: number;
    assumptions?: string[];
    unresolvedQuestions?: string[];
    createdBy?: InvestigationHypothesis['createdBy'];
  }>;
  openQuestions?: string[];
}

export interface UpdateInvestigationInput {
  title?: string;
  objective?: string;
  humanContext?: string;
  status?: InvestigationStatus;
  confidence?: number;
}

export interface AddHumanContextInput {
  environmentalKnowledge?: string[];
  suspicions?: string[];
  knownLegitimateBehavior?: string[];
  knownAbnormalBehavior?: string[];
  notes?: string[];
  riskTolerance?: HumanCapabilityContext['riskTolerance'];
  importantEntities?: Array<{
    name: string;
    type: InvestigationEntity['type'];
    summary?: string;
  }>;
}

// ---------------------------------------------------------------------------
// Human interruption (UI → IPC → RuntimeInvestigationOrchestrator)
// ---------------------------------------------------------------------------

/**
 * Simple one-shot interruption actions emitted by the workspace UI
 * (HumanCommandBar / HumanContextPanel / HypothesesPanel). Each kind carries
 * its payload in `value` / `title`+`statement` / `hypothesisId`.
 */
export type HumanInterruptionKind =
  | 'directive'
  | 'direction'
  | 'note'
  | 'suspicion'
  | 'constraint'
  | 'hypothesis'
  | 'promote_hypothesis'
  | 'reject_hypothesis'
  | 'risk_tolerance'
  | 'reject_replan';

export interface HumanInterruptionTaskSpec {
  id: string;
  title: string;
  description: string;
  role: string;
  kind: 'investigative' | 'analysis' | 'challenge' | 'research';
  dependsOn?: string[];
  canRunConcurrently?: boolean;
  mergeStrategy: 'append_evidence' | 'update_hypothesis' | 'append_questions' | 'append_notes';
}

export interface HumanInterruptionHypothesisUpdate {
  hypothesisId: string;
  confidence?: number;
  status?: 'OPEN' | 'SUPPORTED' | 'WEAKENED' | 'REJECTED';
  statement?: string;
  title?: string;
}

/**
 * Canonical payload for `investigation.applyHumanInterruption`.
 *
 * Either a free-form batch interruption (`instruction` + task/evidence
 * directives) or a single `kind`-based action from the workspace UI.
 * `instruction` is optional — the orchestrator derives a human-readable
 * instruction from `kind` + payload when it is absent, and validates the
 * payload before touching investigation state so malformed IPC input can
 * never crash a worker or corrupt shared state.
 */
export interface ApplyHumanInterruptionInput {
  investigationId: string;
  instruction?: string;
  // Batch interruption fields
  addContext?: string[];
  addPriority?: string;
  redirectInvestigationTo?: string;
  ignoreEvidenceIds?: string[];
  pauseTaskIds?: string[];
  cancelTaskIds?: string[];
  reprioritize?: Array<{ plannedTaskId: string; priority: number; rationale?: string }>;
  redirectTasks?: Array<{ plannedTaskId: string; description?: string; role?: string }>;
  createTasks?: HumanInterruptionTaskSpec[];
  hypothesisUpdates?: HumanInterruptionHypothesisUpdate[];
  // Single kind-based action fields
  kind?: HumanInterruptionKind;
  value?: string;
  title?: string;
  statement?: string;
  hypothesisId?: string;
}
