/**
 * @module main/demo/demo-scenario-controller
 *
 * KIN Demo Mode — a centralized deterministic scenario controller that drives
 * a REAL investigation through the real InvestigationService so every panel
 * (evidence, hypotheses, tasks/team, graph, timeline, report) renders actual
 * application state. No LLM, no network: the scenario script below decides
 * which evidence appears, which specialist acts, and which hypothesis
 * changes; the state around it is genuine.
 *
 * Isolation: the controller only *uses* the live service APIs — it does not
 * modify any live-mode code path. The investigation is watermarked
 * "[DEMO MODE]" and the UI renders a persistent DEMO MODE indicator.
 *
 * Approval gates: the scenario physically stops (no timers pending) until
 * the human answers via `approve()` / `deny()`. DENY ends the run honestly.
 */

import type { ServerEvent } from '../../renderer/types';
import type { InvestigationService } from '../investigation/investigation-service';
import {
  DEMO_MODE_TITLE_PREFIX,
  DEMO_MODE_WATERMARK,
  type DemoApprovalRequest,
  type DemoComputerAction,
  type DemoContextSection,
  type DemoControllerState,
  type DemoEvidenceRef,
  type DemoHypothesisRef,
  type DemoNextStep,
  type DemoSpecialist,
  type DemoTeammateMessage,
} from '../../shared/cyber/demo-types';

export interface DemoScenarioControllerOptions {
  /** Base delay between scripted transitions (ms). Configurable for tests. */
  stepDelayMs?: number;
}

interface ControllerDeps {
  investigationService: InvestigationService;
  sendToRenderer: (event: ServerEvent) => void;
}

type Timer = ReturnType<typeof setTimeout>;

export class DemoScenarioController {
  private state: DemoControllerState;
  private readonly timers = new Set<Timer>();
  private readonly evidenceIds = new Map<string, string>();
  private readonly hypothesisIds = new Map<string, string>();
  private readonly taskIds = new Map<string, string>();
  private pendingApproval: DemoApprovalRequest | null = null;
  private resolveApproval: ((approved: boolean) => void) | null = null;

  constructor(
    private readonly deps: ControllerDeps,
    private readonly options: DemoScenarioControllerOptions = {}
  ) {
    this.state = this.initialState();
  }

  // ---------------------------------------------------------------------------
  // Public API (wired to demo.* IPC)
  // ---------------------------------------------------------------------------

  snapshot(): DemoControllerState {
    return this.state;
  }

  isRunning(): boolean {
    return this.state.phase !== 'idle';
  }

  /** Start the demo scenario. Returns the created investigation id. */
  start(): { investigationId: string } {
    this.resetRuntime();
    const investigation = this.deps.investigationService.create({
      title: `${DEMO_MODE_TITLE_PREFIX} Suspicious PowerShell Activity`,
      objective:
        'Determine whether suspicious PowerShell activity on DEMO-WIN-01 is malicious document-driven execution, and produce an analyst-ready conclusion.',
      humanContext: [
        `${DEMO_MODE_WATERMARK}: deterministic demo scenario (offline, synthetic data).`,
        'Endpoint: DEMO-WIN-01. User: demo.user. Incident: Suspicious PowerShell Execution.',
        'Do not act on this evidence against any real system.',
      ].join('\n'),
      riskTolerance: 'MEDIUM',
    });
    const investigationId = investigation.id;
    this.state.investigationId = investigationId;
    this.state.startedAt = Date.now();
    this.setPhase('building-context', 'Investigating');
    this.say(
      'Investigation opened on DEMO-WIN-01. I am pulling the environment context before I look at anything suspicious.'
    );
    this.deps.investigationService.resume(investigationId);
    this.syncInvestigation();
    this.emitState();

    this.schedule(400, () => this.buildContextStep(0));
    return { investigationId };
  }

  /** Human approved the pending action. Resolves the gate; scenario continues. */
  approve(stepId: string): { success: boolean } {
    if (!this.pendingApproval || this.pendingApproval.stepId !== stepId) {
      return { success: false };
    }
    this.pendingApproval = { ...this.pendingApproval, status: 'approved' };
    this.state.approval = this.pendingApproval;
    this.recordOperational(`Human approved: ${this.pendingApproval.title}`, {
      approvalStepId: stepId,
      decision: 'approved',
      actor: 'human',
    });
    this.say('Approved. Executing now — read-only, on the demo endpoint.');
    const resolve = this.resolveApproval;
    this.resolveApproval = null;
    resolve?.(true);
    this.emitState();
    // Continue the deterministic script into the approved computer-use stage.
    const stage: 1 | 2 = stepId === 'step-2' ? 2 : 1;
    this.schedule(300, () => this.runComputerUse(stage));
    return { success: true };
  }

  /** Human declined the pending action. The scenario stops honestly. */
  deny(stepId: string): { success: boolean } {
    if (!this.pendingApproval || this.pendingApproval.stepId !== stepId) {
      return { success: false };
    }
    this.pendingApproval = { ...this.pendingApproval, status: 'denied' };
    this.state.approval = this.pendingApproval;
    this.recordOperational(`Human declined: ${this.pendingApproval.title}`, {
      approvalStepId: stepId,
      decision: 'denied',
      actor: 'human',
    });
    this.clearTimers();
    this.resolveApproval = null;
    this.setPhase('denied', 'Stopped by human');
    this.say(
      'Understood — I will not run that action. The investigation stays at its current state; nothing was executed. You can restart the demo at any time.'
    );
    this.emitState();
    return { success: true };
  }

  /** Archive the current demo investigation and start a fresh scenario. */
  restart(): { investigationId: string } {
    if (this.state.investigationId) {
      try {
        this.deps.investigationService.archive(this.state.investigationId);
      } catch {
        // Investigation may already be gone; restarting must never fail here.
      }
    }
    return this.start();
  }

  /** Cancel timers (app shutdown safety). */
  dispose(): void {
    this.clearTimers();
  }

  // ---------------------------------------------------------------------------
  // Scenario script — deterministic steps
  // ---------------------------------------------------------------------------

  private buildContextStep(index: number): void {
    const updates: Array<{ detail: string }> = [
      { detail: 'DEMO-WIN-01 (Windows 11, synthetic)' },
      { detail: 'demo.user (standard user)' },
      { detail: 'Available — endpoint telemetry streaming' },
      { detail: 'Available — 4611/4624 synthetic events' },
      { detail: 'Available — synthetic DNS + HTTP proxy' },
      { detail: 'Available — synthetic file telemetry' },
      { detail: 'None — first investigation for this host' },
      { detail: 'Active — collecting' },
    ];
    if (index < this.state.contextRoot.length) {
      const section = this.state.contextRoot[index];
      section.status = 'ready';
      section.detail = updates[index]?.detail ?? section.detail;
    }
    if (index === 3) {
      this.say('Context assembled so far: host, user, and four telemetry sources. Building the rest now.');
    }
    this.emitState();
    if (index + 1 < this.state.contextRoot.length) {
      this.schedule(420, () => this.buildContextStep(index + 1));
    } else {
      this.schedule(600, () => this.detectSignal());
    }
  }

  private detectSignal(): void {
    this.setPhase('signal-detected', 'Investigating');
    this.state.signal = {
      parent: 'WINWORD.EXE',
      child: 'powershell.exe',
      summary: 'Suspicious process relationship detected — document process spawning PowerShell.',
    };
    this.say('Detection pulled me in: WINWORD.EXE spawned powershell.exe with a suspicious command line. Opening a case and starting my team.');

    const inv = this.requireInvestigation();
    const svc = this.deps.investigationService;
    // Anchoring entities for the graph.
    const host = svc.addEntity(inv.id, { name: 'DEMO-WIN-01', type: 'host', summary: 'Demo endpoint (synthetic)' });
    const winword = svc.addEntity(inv.id, { name: 'WINWORD.EXE', type: 'process', summary: 'Word process on DEMO-WIN-01' });
    const ps = svc.addEntity(inv.id, { name: 'powershell.exe', type: 'process', summary: 'PowerShell child of WINWORD.EXE' });
    this.entityIds.set('host', host.entities.at(-1)!.id);
    this.entityIds.set('winword', winword.entities.at(-1)!.id);
    this.entityIds.set('powershell', ps.entities.at(-1)!.id);

    // E-001 — the detection.
    this.addTaggedEvidence('E-001', {
      type: 'OBSERVATION',
      title: 'E-001 — Process Event: WINWORD.EXE → powershell.exe',
      source: 'Endpoint Telemetry',
      timestamp: Date.now(),
      investigator: 'Detection Analyst',
      relatedEntityIds: [this.entityIds.get('winword')!, this.entityIds.get('powershell')!, this.entityIds.get('host')!],
      content: 'WINWORD.EXE (parent) spawned powershell.exe (child). Trust: HIGH. Potentially unusual execution chain.',
      confidence: 0.9,
      provenance: { method: 'tool_output', sourceType: 'log', sourceId: 'demo-etlemetry-001', collectedBy: 'Detection Analyst' },
      hypothesisIds: [],
      kind: 'structured_record',
      summary: 'Office application spawned PowerShell — classic suspicious execution chain shape.',
      tags: ['process-event', 'demo'],
    });
    svc.addGraphRelationship(inv.id, {
      type: 'SPAWNED',
      sourceEntityId: this.entityIds.get('winword')!,
      targetEntityId: this.entityIds.get('powershell')!,
      source: 'Endpoint Telemetry',
      confidence: 0.95,
      evidenceIds: [this.evidenceIds.get('E-001')!],
    });
    this.syncInvestigation();
    this.emitState();

    this.schedule(900, () => this.startSpecialists());
  }

  private startSpecialists(): void {
    this.setPhase('specialists-working', 'Investigating');
    const svc = this.deps.investigationService;
    const inv = this.requireInvestigation();
    const roles: Array<{ key: string; role: string; title: string; description: string }> = [
      { key: 'detection', role: 'Detection Analyst', title: 'Triage detection: WINWORD → PowerShell', description: 'Validate the detection signal and process relationship.' },
      { key: 'endpoint', role: 'Endpoint Analyst', title: 'Examine process lineage on DEMO-WIN-01', description: 'Reconstruct the process tree around powershell.exe.' },
      { key: 'evidence', role: 'Evidence Analyst', title: 'Correlate endpoint, network, and file events', description: 'Find events that support or contradict the execution chain.' },
      { key: 'threat', role: 'Threat Analyst', title: 'Assess adversary technique match', description: 'Map confirmed behavior to known document-driven execution techniques.' },
    ];
    for (const item of roles) {
      const updated = svc.addTask(inv.id, {
        title: item.title,
        description: item.description,
        type: 'AI',
        owner: item.role,
        status: 'CREATED',
        priority: 1,
      });
      this.taskIds.set(item.key, updated.aiTasks.at(-1)!.id);
    }
    this.state.specialists = roles.map((item) => ({ role: item.role, status: 'waiting' }));
    this.setSpecialist('Detection Analyst', 'analyzing');
    this.say('KIN team assembled. Detection Analyst is validating the signal first.');
    this.syncInvestigation();
    this.emitState();

    this.schedule(700, () => this.detectionFinding());
  }

  private detectionFinding(): void {
    const svc = this.deps.investigationService;
    const inv = this.requireInvestigation();
    svc.updateTask(inv.id, this.taskIds.get('detection')!, { status: 'COMPLETED' });
    this.setSpecialist('Detection Analyst', 'done', '✓ identified suspicious execution');
    this.setSpecialist('Endpoint Analyst', 'analyzing');
    this.say('Detection Analyst confirmed the chain is real, not a telemetry glitch. Endpoint Analyst is examining the process lineage.');
    this.syncInvestigation();
    this.emitState();
    this.schedule(900, () => this.endpointFinding());
  }

  private endpointFinding(): void {
    const svc = this.deps.investigationService;
    const inv = this.requireInvestigation();
    svc.updateTask(inv.id, this.taskIds.get('endpoint')!, { status: 'COMPLETED' });
    this.setSpecialist('Endpoint Analyst', 'done', '✓ parent is WINWORD.EXE (office suite), not a shell or scheduler');
    this.setSpecialist('Evidence Analyst', 'analyzing');
    this.say('Endpoint Analyst: the parent is WINWORD.EXE — an office document context, not an admin tool. That raises my interest.');
    this.syncInvestigation();
    this.emitState();
    this.schedule(800, () => this.correlateStep(0));
  }

  private correlateStep(index: number): void {
    this.setPhase('correlating', 'Investigating');
    const svc = this.deps.investigationService;
    const inv = this.requireInvestigation();

    if (index === 0) {
      // E-002 — command line.
      this.addTaggedEvidence('E-002', {
        type: 'OBSERVATION',
        title: 'E-002 — PowerShell Command Line: -ExecutionPolicy Bypass',
        source: 'Endpoint Telemetry',
        timestamp: Date.now(),
        investigator: 'Evidence Analyst',
        relatedEntityIds: [this.entityIds.get('powershell')!],
        content: 'powershell.exe launched with -ExecutionPolicy Bypass and an encoded command fragment. Trust: HIGH.',
        confidence: 0.9,
        provenance: { method: 'tool_output', sourceType: 'log', sourceId: 'demo-etlemetry-002', collectedBy: 'Evidence Analyst' },
        hypothesisIds: [],
        kind: 'structured_record',
        summary: 'Execution-policy bypass is atypical for ordinary user activity.',
        tags: ['command-line', 'demo'],
      });
      this.say('Evidence Analyst is correlating events. First find: the PowerShell command used -ExecutionPolicy Bypass.');
    } else if (index === 1) {
      // E-003 — network event.
      const ipEntity = svc.addEntity(inv.id, { name: '203.0.113.42', type: 'ip', summary: 'Synthetic external destination (documentation IP)' });
      this.entityIds.set('dest-ip', ipEntity.entities.at(-1)!.id);
      this.addTaggedEvidence('E-003', {
        type: 'OBSERVATION',
        title: 'E-003 — Network Event: powershell.exe → 203.0.113.42',
        source: 'Network Telemetry',
        timestamp: Date.now(),
        investigator: 'Evidence Analyst',
        relatedEntityIds: [this.entityIds.get('powershell')!, this.entityIds.get('dest-ip')!],
        content: 'powershell.exe initiated a connection to external host 203.0.113.42 (synthetic). Trust: HIGH.',
        confidence: 0.85,
        provenance: { method: 'tool_output', sourceType: 'log', sourceId: 'demo-network-003', collectedBy: 'Evidence Analyst' },
        hypothesisIds: [],
        kind: 'structured_record',
        summary: 'Script-initiated outbound connection shortly after execution.',
        tags: ['network', 'demo'],
      });
      svc.addGraphRelationship(inv.id, {
        type: 'CONNECTED_TO',
        sourceEntityId: this.entityIds.get('powershell')!,
        targetEntityId: this.entityIds.get('dest-ip')!,
        source: 'Network Telemetry',
        confidence: 0.9,
        evidenceIds: [this.evidenceIds.get('E-003')!],
      });
      this.say('Second find: the same PowerShell process reached out to an external address right after launch. (Synthetic destination — never contacted.)');
    } else if (index === 2) {
      // E-004 — document event.
      const docEntity = svc.addEntity(inv.id, { name: 'invoice_review.docm', type: 'file', summary: 'Macro-enabled document opened before the spawn' });
      this.entityIds.set('doc', docEntity.entities.at(-1)!.id);
      this.addTaggedEvidence('E-004', {
        type: 'OBSERVATION',
        title: 'E-004 — Document Event: WINWORD.EXE opened invoice_review.docm',
        source: 'File Telemetry',
        timestamp: Date.now(),
        investigator: 'Evidence Analyst',
        relatedEntityIds: [this.entityIds.get('winword')!, this.entityIds.get('doc')!],
        content: 'WINWORD.EXE opened invoice_review.docm (macro-enabled) 12 seconds before the PowerShell spawn. Trust: HIGH.',
        confidence: 0.9,
        provenance: { method: 'tool_output', sourceType: 'log', sourceId: 'demo-file-004', collectedBy: 'Evidence Analyst' },
        hypothesisIds: [],
        kind: 'structured_record',
        summary: 'Macro-enabled document immediately precedes the execution chain.',
        tags: ['document', 'demo'],
      });
      svc.addGraphRelationship(inv.id, {
        type: 'ACCESSED',
        sourceEntityId: this.entityIds.get('winword')!,
        targetEntityId: this.entityIds.get('doc')!,
        source: 'File Telemetry',
        confidence: 0.9,
        evidenceIds: [this.evidenceIds.get('E-004')!],
      });
      this.setSpecialist('Evidence Analyst', 'done', '✓ correlated 4 events into one chain');
      this.state.correlationChain = ['invoice_review.docm', 'WINWORD.EXE', 'powershell.exe', 'suspicious command', 'network activity'];
      this.say('I have correlated three events that point toward the same execution chain: document → Word → PowerShell → network.');
      this.syncInvestigation();
      this.emitState();
      this.schedule(900, () => this.formHypotheses());
      return;
    }
    this.syncInvestigation();
    this.emitState();
    this.schedule(850, () => this.correlateStep(index + 1));
  }

  private formHypotheses(): void {
    this.setPhase('forming-hypotheses', 'Investigating');
    const svc = this.deps.investigationService;
    const inv = this.requireInvestigation();

    const h1 = svc.addHypothesis(inv.id, {
      title: 'H1 — Malicious document execution',
      statement: 'invoice_review.docm delivered macro code that spawned PowerShell to fetch or stage a payload.',
      confidence: 0.2,
      createdBy: 'agent',
    });
    const h2 = svc.addHypothesis(inv.id, {
      title: 'H2 — Legitimate administrative activity',
      statement: 'A user or script legitimately ran PowerShell from Word (e.g., an approved macro add-in).',
      confidence: 0.5,
      createdBy: 'agent',
    });
    this.hypothesisIds.set('H1', h1.hypotheses.at(-1)!.id);
    this.hypothesisIds.set('H2', h2.hypotheses.at(-1)!.id);

    // Evidence assessments — the real hypothesis service computes confidence
    // and status from these links (±0.15 per assessment), so the hypothesis
    // panel shows genuine service-computed evolution, not scripted numbers.
    const link = (hypTag: string, evTag: string, relationship: 'SUPPORTS' | 'WEAKENS', rationale: string) => {
      svc.applyEvidenceToHypothesis(inv.id, {
        hypothesisId: this.hypothesisIds.get(hypTag)!,
        evidenceId: this.evidenceIds.get(evTag)!,
        relationship,
        rationale,
        actor: 'agent',
      });
    };
    link('H1', 'E-001', 'SUPPORTS', 'Document process spawned the script host.');
    link('H1', 'E-003', 'SUPPORTS', 'Script-initiated outbound connection fits payload staging.');
    link('H1', 'E-004', 'SUPPORTS', 'Macro-enabled document immediately preceded the spawn.');
    link('H2', 'E-002', 'WEAKENS', 'Ordinary business macros rarely bypass execution policy.');
    link('H2', 'E-004', 'WEAKENS', 'Unsolicited .docm execution is not standard admin flow.');

    this.refreshHypothesisRefs();
    this.setSpecialist('Threat Analyst', 'analyzing');
    this.say(
      'I have two competing explanations. The evidence currently favors H1 (malicious document execution), but one key question remains unresolved.'
    );
    this.syncInvestigation();
    this.emitState();
    this.schedule(900, () => this.acknowledgeUnknowns());
  }

  private acknowledgeUnknowns(): void {
    this.setPhase('acknowledging-unknowns', 'Investigating');
    const svc = this.deps.investigationService;
    const inv = this.requireInvestigation();
    const unknowns = [
      'The origin of invoice_review.docm is not yet confirmed.',
      'The process lineage does not establish whether the PowerShell command completed successfully.',
    ];
    for (const question of unknowns) {
      svc.addOpenQuestion(inv.id, question);
    }
    this.state.unknowns = unknowns;
    this.say('What I do not know yet: where the document came from, and whether the PowerShell command actually completed. I will not pretend otherwise.');
    this.syncInvestigation();
    this.emitState();
    this.schedule(900, () => this.recommendFirstStep());
  }

  private recommendFirstStep(): void {
    const nextStep: DemoNextStep = {
      id: 'step-1',
      title: 'Inspect the PowerShell process tree and command execution result on DEMO-WIN-01',
      why: 'This will determine whether the suspicious execution actually completed — the single fact that best separates H1 from H2 right now.',
      expectedValue: 'HIGH',
      risk: 'Read-only',
    };
    this.setPhase('awaiting-approval', 'Awaiting your approval');
    this.state.nextStep = nextStep;
    this.pendingApproval = {
      stepId: nextStep.id,
      title: 'Inspect PowerShell process information',
      target: 'DEMO-WIN-01',
      purpose: 'Validate the suspicious execution chain (read-only process telemetry).',
      risk: 'Read-only',
      status: 'pending',
    };
    this.state.approval = this.pendingApproval;
    this.recordOperational('Next best step selected: inspect PowerShell process tree (expected value: HIGH)', {
      stepId: nextStep.id,
      why: nextStep.why,
      expectedValue: nextStep.expectedValue,
      requiresApproval: true,
    });
    this.say('The highest-value next step is to inspect the PowerShell process tree. This action is read-only — I need your approval before I execute it.');
    this.emitState();
    // Hard stop: no timers. The scenario waits for the human.
  }

  private runComputerUse(stage: 1 | 2): void {
    this.setPhase('computer-use', 'Executing approved action');
    const actions: Array<{ action: string; target: string; observation: string }> = stage === 1
      ? [
          { action: 'connect', target: 'DEMO-WIN-01 (synthetic endpoint console)', observation: 'Connected to the demo endpoint environment.' },
          { action: 'inspect_process_tree', target: 'powershell.exe (PID 4821, synthetic)', observation: 'Parent WINWORD.EXE (PID 3312). Command: powershell -nop -w hidden -enc SQBFAFgA… (truncated synthetic).' },
          { action: 'read_execution_result', target: 'PowerShell synthetic event log', observation: 'Script execution completed (exit code 0). Output file written to %TEMP%.' },
          { action: 'screenshot', target: 'Process inspector view', observation: 'Captured process inspector panel showing the WINWORD → PowerShell lineage.' },
        ]
      : [
          { action: 'inspect_startup_items', target: 'synthetic Startup folder + Run keys', observation: 'No new Run-key or Startup-folder entries in the last 24h.' },
          { action: 'list_scheduled_tasks', target: 'synthetic task scheduler', observation: 'No task created or modified around the incident window.' },
        ];

    this.state.computerActions = actions.map((item, idx) => ({
      id: `cu-${stage}-${idx}`,
      tool: 'computer_use' as const,
      action: item.action,
      target: item.target,
      status: 'pending' as const,
    }));
    this.say(stage === 1
      ? 'Running the approved inspection on the demo endpoint now — watch the action stream.'
      : 'Checking persistence locations next — startup items and scheduled tasks.');
    this.emitState();

    actions.forEach((item, idx) => {
      this.schedule(300 + idx * 750, () => {
        const entry = this.state.computerActions[idx];
        entry.status = 'done';
        entry.observation = item.observation;
        this.recordOperational(`Computer use (${item.action}) on ${item.target}`, {
          computerActionId: entry.id,
          tool: 'computer_use',
          action: item.action,
          target: item.target,
          observation: item.observation,
          approvedBy: 'human',
        });
        this.emitState();
        if (idx === actions.length - 1) {
          this.schedule(500, () => (stage === 1 ? this.newEvidenceFromComputerUse() : this.persistenceResult()));
        }
      });
    });
  }

  private newEvidenceFromComputerUse(): void {
    this.setPhase('new-evidence', 'Investigating');
    this.addTaggedEvidence('E-005', {
      type: 'OBSERVATION',
      title: 'E-005 — Confirmed Execution: PowerShell completed under WINWORD.EXE',
      source: 'Live Endpoint Inspection (approved)',
      timestamp: Date.now(),
      investigator: 'Endpoint Analyst',
      relatedEntityIds: [this.entityIds.get('winword')!, this.entityIds.get('powershell')!],
      content:
        'Process inspection confirmed: parent WINWORD.EXE, hidden-window PowerShell with encoded command, execution COMPLETED with exit code 0 and wrote an output file to %TEMP%. Trust: HIGH (collected after human approval).',
      confidence: 0.95,
      provenance: { method: 'tool_output', sourceType: 'tool_execution', sourceId: 'demo-cu-stage-1', sourceLabel: 'Computer use — approved inspection (demo endpoint)', collectedBy: 'KIN (approved action)' },
      hypothesisIds: [],
      kind: 'structured_record',
      summary: 'The suspicious execution did run to completion — the key open question is answered.',
      tags: ['computer-use', 'confirmed-execution', 'demo'],
    });
    this.say('New evidence is in: the PowerShell command did complete. E-005 is added to the case.');
    this.syncInvestigation();
    this.emitState();
    this.schedule(800, () => this.updateHypotheses());
  }

  private updateHypotheses(): void {
    this.setPhase('updating-hypotheses', 'Investigating');
    const svc = this.deps.investigationService;
    const inv = this.requireInvestigation();
    const h1Id = this.hypothesisIds.get('H1')!;
    const h2Id = this.hypothesisIds.get('H2')!;
    svc.applyEvidenceToHypothesis(inv.id, {
      hypothesisId: h1Id,
      evidenceId: this.evidenceIds.get('E-005')!,
      relationship: 'SUPPORTS',
      rationale: 'Confirmed completion of the encoded-command execution is the behavior H1 predicts.',
      actor: 'agent',
    });
    svc.applyEvidenceToHypothesis(inv.id, {
      hypothesisId: h1Id,
      evidenceId: this.evidenceIds.get('E-002')!,
      relationship: 'SUPPORTS',
      rationale: 'With execution confirmed, the ExecutionPolicy Bypass command line clearly fits staged macro execution.',
      actor: 'agent',
    });
    svc.applyEvidenceToHypothesis(inv.id, {
      hypothesisId: h2Id,
      evidenceId: this.evidenceIds.get('E-005')!,
      relationship: 'WEAKENS',
      rationale: 'Hidden-window encoded execution with a completed callback is not legitimate admin behavior.',
      actor: 'agent',
    });
    this.refreshHypothesisRefs();
    this.setSpecialist('Threat Analyst', 'done', '✓ matches document-driven execution technique pattern');
    this.say('The new evidence strengthens H1 and weakens H2. Threat Analyst mapped the chain to a known document-driven execution pattern.');
    this.syncInvestigation();
    this.emitState();
    this.schedule(900, () => this.recommendSecondStep());
  }

  private recommendSecondStep(): void {
    const nextStep: DemoNextStep = {
      id: 'step-2',
      title: 'Check startup/persistence indicators on DEMO-WIN-01 (Run keys, Startup folder, scheduled tasks)',
      why: 'H1 is supported, but I cannot confirm persistence from current evidence — this decides whether this is contained or established.',
      expectedValue: 'HIGH',
      risk: 'Read-only',
    };
    this.setPhase('awaiting-approval', 'Awaiting your approval');
    this.state.nextStep = nextStep;
    this.pendingApproval = {
      stepId: nextStep.id,
      title: 'Inspect persistence indicators',
      target: 'DEMO-WIN-01',
      purpose: 'Determine whether the activity established persistence (read-only checks).',
      risk: 'Read-only',
      status: 'pending',
    };
    this.state.approval = this.pendingApproval;
    this.recordOperational('Next best step selected: inspect persistence indicators (expected value: HIGH)', {
      stepId: nextStep.id,
      why: nextStep.why,
      requiresApproval: true,
    });
    this.say('The evidence now supports suspicious document-driven PowerShell execution. Remaining question: did it establish persistence? I need your approval for read-only persistence checks.');
    this.emitState();
    // Hard stop again for the second approval.
  }

  private persistenceResult(): void {
    this.setPhase('new-evidence', 'Investigating');
    this.addTaggedEvidence('E-006', {
      type: 'OBSERVATION',
      title: 'E-006 — Persistence Check: no persistence indicators found',
      source: 'Live Endpoint Inspection (approved)',
      timestamp: Date.now(),
      investigator: 'Endpoint Analyst',
      relatedEntityIds: [this.entityIds.get('host')!],
      content: 'No Run-key additions, Startup-folder items, or scheduled-task changes in the incident window. Absence evidence — scope limited to checked locations.',
      confidence: 0.6,
      provenance: { method: 'tool_output', sourceType: 'tool_execution', sourceId: 'demo-cu-stage-2', sourceLabel: 'Computer use — approved persistence checks (demo endpoint)', collectedBy: 'KIN (approved action)' },
      hypothesisIds: [],
      kind: 'structured_record',
      summary: 'No persistence found in checked locations; cannot fully rule out mechanisms not covered.',
      tags: ['computer-use', 'persistence', 'demo'],
    });
    this.state.unknowns = [
      'Origin of invoice_review.docm (email vs. web download) — not confirmed.',
      'Persistence: none found in checked locations (Run keys, Startup folder, scheduled tasks); other mechanisms not covered.',
    ];
    this.say('No persistence in the usual locations. I still cannot rule out every mechanism — that stays an explicit unknown.');
    this.syncInvestigation();
    this.emitState();
    this.schedule(900, () => this.conclude());
  }

  private conclude(): void {
    this.setPhase('concluding', 'Concluding');
    const svc = this.deps.investigationService;
    const inv = this.requireInvestigation();
    svc.upsertConclusion(inv.id, {
      summary:
        'Suspicious document-driven PowerShell execution on DEMO-WIN-01 is strongly supported: a macro-enabled document preceded a hidden PowerShell execution that completed and contacted an external host. No persistence found in checked locations; document origin remains unconfirmed.',
      confidence: 0.9,
      rationale:
        'E-001/E-004 establish the chain; E-005 (approved live inspection) confirms completion; E-006 rules out common persistence. H2 remains disfavored by E-002/E-004/E-005.',
      derivedFromHypothesisIds: [this.hypothesisIds.get('H1')!],
      derivedFromEvidenceIds: ['E-001', 'E-002', 'E-004', 'E-005', 'E-006']
        .map((tag) => this.evidenceIds.get(tag))
        .filter((id): id is string => Boolean(id)),
    });
    this.deps.investigationService.update(inv.id, { status: 'CONCLUDED' });
    this.state.conclusion = {
      assessment:
        'Suspicious document-driven PowerShell execution is strongly supported by the available evidence.',
      confidence: 'HIGH',
      confidencePercent: 90,
      supportingEvidenceTags: ['E-001', 'E-002', 'E-004', 'E-005'],
      remainingUnknowns: this.state.unknowns,
      recommendedNextSteps: [
        'Continue endpoint persistence analysis (broader mechanisms).',
        'Confirm the delivery vector of invoice_review.docm.',
        'Block 203.0.113.42 at the perimeter and hunt for the same chain on other hosts.',
      ],
    };
    // Generate the report through the real report pipeline (REPORT_GENERATED
    // event; InvestigationReportPanel renders the same state on demand).
    this.deps.investigationService.generateReport(inv.id);
    this.setPhase('complete', 'Concluded');
    this.say('Investigation concluded — full report generated below from the case record. This is strong evidence, not 100% certainty: two unknowns remain open.');
    this.recordOperational('Investigation concluded (demo). Confidence HIGH (90%). Two unknowns documented.', {
      conclusionConfidence: 0.9,
    });
    this.syncInvestigation();
    this.emitState();
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private initialState(): DemoControllerState {
    return {
      version: 1,
      scenarioId: 'suspicious-powershell-demo',
      phase: 'idle',
      investigationId: null,
      startedAt: null,
      statusLabel: 'Idle',
      contextRoot: [
        { key: 'endpoint', label: 'Endpoint', detail: '', status: 'pending' },
        { key: 'user', label: 'User', detail: '', status: 'pending' },
        { key: 'process', label: 'Process Activity', detail: '', status: 'pending' },
        { key: 'auth', label: 'Authentication Events', detail: '', status: 'pending' },
        { key: 'network', label: 'Network Events', detail: '', status: 'pending' },
        { key: 'file', label: 'File Events', detail: '', status: 'pending' },
        { key: 'previous', label: 'Previous Evidence', detail: '', status: 'pending' },
        { key: 'state', label: 'Investigation State', detail: '', status: 'pending' },
      ],
      specialists: [],
      messages: [],
      signal: null,
      correlationChain: [],
      evidence: [],
      hypotheses: [],
      unknowns: [],
      nextStep: null,
      approval: null,
      computerActions: [],
      conclusion: null,
    };
  }

  private resetRuntime(): void {
    this.clearTimers();
    this.pendingApproval = null;
    this.resolveApproval = null;
    this.evidenceIds.clear();
    this.hypothesisIds.clear();
    this.taskIds.clear();
    this.entityIds.clear();
    this.state = this.initialState();
  }

  private entityIds = new Map<string, string>();

  private requireInvestigation() {
    const id = this.state.investigationId;
    if (!id) throw new Error('Demo scenario: no active investigation');
    const investigation = this.deps.investigationService.get(id);
    if (!investigation) throw new Error(`Demo scenario: investigation not found: ${id}`);
    return investigation;
  }

  private setPhase(phase: DemoControllerState['phase'], statusLabel: string): void {
    this.state.phase = phase;
    this.state.statusLabel = statusLabel;
  }

  private say(text: string): void {
    this.state.messages.push({ id: `msg-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`, text, timestamp: Date.now() });
    this.recordOperational(text, { teammateMessage: true });
  }

  private setSpecialist(role: string, status: DemoSpecialist['status'], finding?: string): void {
    const entry = this.state.specialists.find((item) => item.role === role);
    if (!entry) return;
    entry.status = status;
    if (finding !== undefined) entry.finding = finding;
  }

  private addTaggedEvidence(tag: string, input: Parameters<InvestigationService['addEvidence']>[1]): void {
    const inv = this.requireInvestigation();
    const updated = this.deps.investigationService.addEvidence(inv.id, input);
    const added = updated.evidence.at(-1)!;
    this.evidenceIds.set(tag, added.id);
    this.state.evidence = [
      ...this.state.evidence.filter((item) => item.tag !== tag),
      { tag, evidenceId: added.id, title: added.title },
    ];
  }

  private refreshHypothesisRefs(): void {
    const inv = this.requireInvestigation();
    const refs: DemoHypothesisRef[] = [];
    for (const [tag, id] of this.hypothesisIds) {
      const hyp = inv.hypotheses.find((item) => item.id === id);
      if (!hyp) continue;
      refs.push({
        tag,
        hypothesisId: id,
        title: hyp.title,
        confidence: hyp.confidence,
        confidenceLabel: hyp.confidenceAssessment,
        status: hyp.status,
      });
    }
    refs.sort((a, b) => a.tag.localeCompare(b.tag));
    this.state.hypotheses = refs;
  }

  private recordOperational(summary: string, data: Record<string, unknown>): void {
    const id = this.state.investigationId;
    if (!id) return;
    this.deps.investigationService.recordEvent(id, 'OPERATIONAL_UPDATE', 'system', summary, {
      ...data,
      demoMode: true,
      watermark: DEMO_MODE_WATERMARK,
    });
  }

  /** Push the current investigation record to the renderer (real state sync). */
  private syncInvestigation(): void {
    const id = this.state.investigationId;
    if (!id) return;
    const investigation = this.deps.investigationService.get(id);
    if (!investigation) return;
    this.deps.sendToRenderer({ type: 'investigation.updated', payload: { investigation } });
    this.deps.sendToRenderer({
      type: 'investigation.list',
      payload: { investigations: this.deps.investigationService.list() },
    });
  }

  private emitState(): void {
    this.deps.sendToRenderer({ type: 'demo.state', payload: { state: this.snapshot() } });
  }

  private schedule(delayMs: number, fn: () => void): void {
    // delayMs values are presentation timings on an 800ms basis;
    // stepDelayMs rescales the whole scenario (1 = real time, 0.005 = tests).
    const scale = (this.options.stepDelayMs ?? 800) / 800;
    const timer = setTimeout(() => {
      this.timers.delete(timer);
      try {
        fn();
      } catch (error) {
        // A scripted step must never silently die: surface it in the stream.
        this.say(`Scenario step failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    }, Math.max(0, Math.round(delayMs * scale)));
    this.timers.add(timer);
  }

  private clearTimers(): void {
    for (const timer of this.timers) clearTimeout(timer);
    this.timers.clear();
  }
}

// Re-export for controller consumers.
export type {
  DemoApprovalRequest,
  DemoComputerAction,
  DemoContextSection,
  DemoControllerState,
  DemoEvidenceRef,
  DemoHypothesisRef,
  DemoNextStep,
  DemoSpecialist,
  DemoTeammateMessage,
};
