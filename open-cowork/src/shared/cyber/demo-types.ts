/**
 * @module shared/cyber/demo-types
 *
 * Contract for KIN Demo Mode — a deterministic, presentation-ready
 * investigation scenario driven by the main-process DemoScenarioController.
 *
 * REAL application behavior: the controller creates a genuine Investigation
 * through InvestigationService (evidence, hypotheses, tasks, graph, timeline
 * events, conclusion, report are real persisted objects rendered by the real
 * workspace panels). DETERMINISTIC intelligence: which evidence appears and
 * what each specialist concludes is scripted so the demo is reproducible and
 * fully offline.
 */

export type DemoPhase =
  | 'idle'
  | 'building-context'
  | 'signal-detected'
  | 'specialists-working'
  | 'correlating'
  | 'forming-hypotheses'
  | 'acknowledging-unknowns'
  | 'awaiting-approval'
  | 'computer-use'
  | 'new-evidence'
  | 'updating-hypotheses'
  | 'concluding'
  | 'complete'
  | 'denied';

export type DemoSectionStatus = 'pending' | 'loading' | 'ready';

export interface DemoContextSection {
  key: string;
  label: string;
  detail: string;
  status: DemoSectionStatus;
}

export interface DemoSpecialist {
  role: string;
  status: 'waiting' | 'analyzing' | 'done';
  finding?: string;
}

export interface DemoTeammateMessage {
  id: string;
  text: string;
  timestamp: number;
}

export interface DemoEvidenceRef {
  tag: string;
  evidenceId: string;
  title: string;
}

export interface DemoHypothesisRef {
  tag: string;
  hypothesisId: string;
  title: string;
  confidence: number;
  confidenceLabel: 'LOW' | 'MEDIUM' | 'HIGH';
  status: string;
}

export interface DemoNextStep {
  id: string;
  title: string;
  why: string;
  expectedValue: 'HIGH' | 'MEDIUM' | 'LOW';
  risk: 'Read-only' | 'Low' | 'Medium';
}

export interface DemoApprovalRequest {
  stepId: string;
  title: string;
  target: string;
  purpose: string;
  risk: 'Read-only' | 'Low' | 'Medium';
  status: 'pending' | 'approved' | 'denied';
}

/**
 * One computer-use operation, shaped like a KIN tool call
 * (tool + action + target → observation). Demo Mode runs these through a
 * deterministic local simulation behind the same action/result interface a
 * live Computer Use executor would implement.
 */
export interface DemoComputerAction {
  id: string;
  tool: 'computer_use';
  action: string;
  target: string;
  status: 'pending' | 'running' | 'done';
  observation?: string;
}

export interface DemoConclusion {
  assessment: string;
  confidence: 'MEDIUM' | 'HIGH';
  confidencePercent: number;
  supportingEvidenceTags: string[];
  remainingUnknowns: string[];
  recommendedNextSteps: string[];
}

export interface DemoControllerState {
  version: 1;
  scenarioId: 'suspicious-powershell-demo';
  phase: DemoPhase;
  investigationId: string | null;
  startedAt: number | null;
  /** Phase label for the header (Investigating / Awaiting approval / …). */
  statusLabel: string;
  contextRoot: DemoContextSection[];
  specialists: DemoSpecialist[];
  messages: DemoTeammateMessage[];
  signal: { parent: string; child: string; summary: string } | null;
  correlationChain: string[];
  evidence: DemoEvidenceRef[];
  hypotheses: DemoHypothesisRef[];
  unknowns: string[];
  nextStep: DemoNextStep | null;
  approval: DemoApprovalRequest | null;
  computerActions: DemoComputerAction[];
  conclusion: DemoConclusion | null;
}

export const DEMO_MODE_TITLE_PREFIX = '[DEMO MODE]';
export const DEMO_MODE_WATERMARK = 'KIN_DEMO_MODE';

/** Full snapshot emitted to the renderer after every controller transition. */
export interface DemoStateEvent {
  type: 'demo.state';
  payload: { state: DemoControllerState };
}
