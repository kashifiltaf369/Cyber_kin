/**
 * @module main/investigation/hmpx-types
 *
 * HMPI-X cognitive architecture contracts.
 *
 * These types are pure domain contracts. They do not depend on Electron,
 * React, or the agent runner. They are designed to map onto existing
 * OpenCowork abstractions (InvestigationService, CyberCapabilityRegistry,
 * ParallelTaskManager, etc.) without replacing them.
 */

// ---------------------------------------------------------------------------
// Problem
// ---------------------------------------------------------------------------

export type HMPIXProblemStatus =
  | 'CREATED'
  | 'UNDERSTANDING'
  | 'DECOMPOSING'
  | 'DISCOVERING'
  | 'PROBING'
  | 'SELECTING'
  | 'EXECUTING'
  | 'OBSERVING'
  | 'CRITIQUING'
  | 'REPLANNING'
  | 'WAITING_FOR_HUMAN'
  | 'COMPLETED'
  | 'PAUSED'
  | 'STOPPED';

export interface HMPIXProblem {
  id: string;
  objective: string;
  humanContext: string;
  constraints: string[];
  priority: string[];
  riskTolerance: 'LOW' | 'MEDIUM' | 'HIGH';
  scope: string;
  createdAt: number;
  status: HMPIXProblemStatus;
}

// ---------------------------------------------------------------------------
// SubProblem
// ---------------------------------------------------------------------------

export type HMPIXSubProblemStatus =
  | 'PENDING'
  | 'READY'
  | 'EXECUTING'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED'
  | 'BLOCKED';

export interface HMPIXSubProblem {
  id: string;
  problemId: string;
  title: string;
  description: string;
  status: HMPIXSubProblemStatus;
  priority: number;
  dependsOn: string[];
  createdAt: number;
}

// ---------------------------------------------------------------------------
// Decomposition
// ---------------------------------------------------------------------------

export interface HMPIXDecomposition {
  id: string;
  problemId: string;
  subProblems: HMPIXSubProblem[];
  strategy: string;
  createdAt: number;
}

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

export type HMPIXCapabilityRiskLevel = 'LOW' | 'MEDIUM' | 'HIGH';
export type HMPIXCapabilityCost = 'LOW' | 'MEDIUM' | 'HIGH';

export interface HMPIXCapability {
  id: string;
  name: string;
  description: string;
  domain: string;
  requiredInputs: string[];
  producedOutputs: string[];
  availableTools: string[];
  riskLevel: HMPIXCapabilityRiskLevel;
  estimatedCost: HMPIXCapabilityCost;
  estimatedLatency: number;
  reliability: number;
  specialization: string[];
  probeCapability: boolean;
  executionCapability: boolean;
}

// ---------------------------------------------------------------------------
// CapabilityCandidate
// ---------------------------------------------------------------------------

export interface HMPIXCapabilityCandidate {
  capability: HMPIXCapability;
  relevance: number;
  expectedInformationGain: number;
  confidence: number;
  availability: boolean;
  reasons: string[];
}

// ---------------------------------------------------------------------------
// Probe
// ---------------------------------------------------------------------------

export type HMPIXProbeStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export interface HMPIXProbe {
  id: string;
  problemId: string;
  subProblemId: string;
  capabilityIds: string[];
  status: HMPIXProbeStatus;
  startedAt: number;
  completedAt?: number;
}

// ---------------------------------------------------------------------------
// ProbeResult
// ---------------------------------------------------------------------------

export type HMPIXProbeSignal = 'POSITIVE' | 'NEGATIVE' | 'NEUTRAL' | 'INCONCLUSIVE';

export interface HMPIXProbeResult {
  probeId: string;
  signal: HMPIXProbeSignal;
  confidence: number;
  informationGainEstimate: number;
  recommendedCapabilities: string[];
  rejectedCapabilities: string[];
  reason: string;
  result?: unknown;
}

// ---------------------------------------------------------------------------
// ProbeBudget
// ---------------------------------------------------------------------------

export interface HMPIXProbeBudget {
  maxDepth: number;
  maxCount: number;
  maxCost: number;
  maxLatency: number;
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

export interface HMPIXSelectionEntry {
  capabilityId: string;
  score: number;
  relevance: number;
  expectedInformationGain: number;
  confidence: number;
  cost: number;
  latency: number;
  risk: number;
  availability: boolean;
}

export interface HMPIXRejectedEntry {
  capabilityId: string;
  reason: string;
}

export interface HMPIXSelection {
  id: string;
  problemId: string;
  subProblemId?: string;
  selectedCapabilities: HMPIXSelectionEntry[];
  rejectedCapabilities: HMPIXRejectedEntry[];
  rationale: string;
  createdAt: number;
}

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

export interface HMPIXDecision {
  id: string;
  problemId: string;
  summary: string;
  rationale: string;
  createdAt: number;
}

// ---------------------------------------------------------------------------
// ExecutionIntent
// ---------------------------------------------------------------------------

export type HMPIXExecutionIntentStatus =
  | 'PENDING'
  | 'APPROVED'
  | 'DENIED'
  | 'EXECUTING'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED';

export type HMPIXExecutionRisk = 
  | 'READ_ONLY'
  | 'ANALYSIS'
  | 'LOW_RISK'
  | 'HIGH_RISK'
  | 'DESTRUCTIVE';

export interface HMPIXExecutionIntent {
  id: string;
  problemId: string;
  subProblemId: string;
  capabilityId: string;
  intent: string;
  target: Record<string, unknown>;
  requiredEvidence: string[];
  risk: HMPIXExecutionRisk;
  status: HMPIXExecutionIntentStatus;
  createdAt: number;
}

// ---------------------------------------------------------------------------
// Observation
// ---------------------------------------------------------------------------

export type HMPIXObservationType = 'OBSERVATION' | 'INFERENCE' | 'HYPOTHESIS' | 'UNKNOWN';

export interface HMPIXObservation {
  id: string;
  intentId: string;
  type: HMPIXObservationType;
  content: string;
  confidence: number;
  evidenceIds: string[];
  createdAt: number;
}

// ---------------------------------------------------------------------------
// ReplanDecision
// ---------------------------------------------------------------------------

export type HMPIXReplanTrigger =
  | 'new_evidence'
  | 'probe_result'
  | 'execution_complete'
  | 'execution_failed'
  | 'contradiction_detected'
  | 'human_input'
  | 'human_redirect'
  | 'scope_change'
  | 'confidence_change';

export interface HMPIXRecommendedAction {
  capabilityId: string;
  subProblemId?: string;
  rationale: string;
  priority: number;
}

export interface HMPIXReplanDecision {
  id: string;
  problemId: string;
  trigger: HMPIXReplanTrigger;
  triggerDetails: string;
  uncertaintyBefore: number;
  uncertaintyAfter: number;
  recommendedActions: HMPIXRecommendedAction[];
  createdAt: number;
}

// ---------------------------------------------------------------------------
// CognitiveContext
// ---------------------------------------------------------------------------

export interface HMPIXCognitiveContext {
  problemId: string;
  decomposition: HMPIXDecomposition;
  capabilities: HMPIXCapabilityCandidate[];
  probes: HMPIXProbe[];
  selections: HMPIXSelection[];
  intents: HMPIXExecutionIntent[];
  observations: HMPIXObservation[];
  replanDecisions: HMPIXReplanDecision[];
  decisions: HMPIXDecision[];
  uncertainty: number;
  updatedAt: number;
}

// ---------------------------------------------------------------------------
// HMPI-X Kernel Interface
// ---------------------------------------------------------------------------

export interface HMPIXKernel {
  understand(
    objective: string,
    humanContext: string,
    constraints: string[],
    priorities: string[]
  ): Promise<HMPIXProblem>;

  decompose(problem: HMPIXProblem): Promise<HMPIXDecomposition>;

  discoverCapabilities(
    subProblem: HMPIXSubProblem,
    context: HMPIXCognitiveContext
  ): Promise<HMPIXCapabilityCandidate[]>;

  probe(
    subProblem: HMPIXSubProblem,
    candidates: HMPIXCapabilityCandidate[],
    budget: HMPIXProbeBudget
  ): Promise<HMPIXProbeResult[]>;

  select(
    subProblem: HMPIXSubProblem,
    candidates: HMPIXCapabilityCandidate[],
    probeResults: HMPIXProbeResult[],
    context: HMPIXCognitiveContext
  ): Promise<HMPIXSelection>;

  route(
    selection: HMPIXSelection,
    context: HMPIXCognitiveContext
  ): Promise<HMPIXExecutionIntent[]>;

  observe(intentId: string, result: unknown): Promise<HMPIXObservation>;

  replan(
    problem: HMPIXProblem,
    context: HMPIXCognitiveContext,
    trigger: HMPIXReplanTrigger,
    details: string
  ): Promise<HMPIXReplanDecision>;
}

// ---------------------------------------------------------------------------
// Utility types
// ---------------------------------------------------------------------------

export type HMPIXEventType =
  | 'problem.created'
  | 'problem.decomposed'
  | 'capability.discovered'
  | 'probe.started'
  | 'probe.completed'
  | 'capability.selected'
  | 'task.created'
  | 'task.started'
  | 'task.completed'
  | 'task.failed'
  | 'evidence.created'
  | 'hypothesis.created'
  | 'hypothesis.updated'
  | 'contradiction.detected'
  | 'human.input'
  | 'human.redirected'
  | 'replan.started'
  | 'replan.completed'
  | 'approval.requested'
  | 'approval.granted'
  | 'approval.denied';

export interface HMPIXEvent {
  id: string;
  problemId: string;
  type: HMPIXEventType;
  createdAt: number;
  actor: 'human' | 'agent' | 'system';
  summary: string;
  data?: Record<string, unknown>;
}
