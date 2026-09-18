import type { ContentBlock, Message, Session } from '../../renderer/types';
import type { InvestigationService } from './investigation-service';
import {
  AgentCapabilityRegistry,
  InvestigationPlanner,
  ParallelTaskManager,
  TaskScheduler,
  INVESTIGATION_AGENT_ROLES,
  type InvestigationAgentRole,
  type InvestigationPlan,
  type InvestigationWorkerContext,
  type InvestigationWorkerExecutor,
  type InvestigationWorkerResult,
} from './parallel-investigation-engine';
import { InvestigationReplanner } from './investigation-replanner';
import { validateWorkerResultShape } from './evidence-ingestion-service';
import type { OperationalRationale } from '../../shared/cyber/investigation-types';
import type { ApplyHumanInterruptionInput } from '../../shared/cyber/investigation-types';
import { toOperationalRationale } from '../../shared/cyber/investigation-types';
import { getAgentDefinition } from '../cyber/cyber-agent-definitions';
import { validateAgentOutput } from '../cyber/cyber-agent-output-validator';

export interface InvestigationSessionRuntime {
  startSession(
    title: string,
    prompt: string,
    cwd?: string,
    allowedTools?: string[],
    content?: ContentBlock[],
    memoryEnabled?: boolean
  ): Promise<Session>;
  stopSession(sessionId: string): Promise<void> | void;
  getSession(sessionId: string): Session | null;
  getMessages(sessionId: string): Message[];
}

export interface RuntimeInvestigationOrchestratorOptions {
  planner?: InvestigationPlanner;
  scheduler?: TaskScheduler;
  maxRetries?: number;
  pollIntervalMs?: number;
  workerAllowedTools?: string[];
  /**
   * Returns the app's configured workspace directory for worker sessions.
   * Workers must run in the user's workspace — never a hardcoded path and
   * never a silent fallback to the process working directory. When this
   * returns null/undefined, worker execution fails loudly instead.
   */
  getWorkspaceCwd?: () => string | null | undefined;
}

/** Batch-shaped human interruption payload after normalization/validation. */
interface HumanInterruptionBatch {
  instruction: string;
  addContext?: string[];
  addPriority?: string;
  redirectInvestigationTo?: string;
  ignoreEvidenceIds?: string[];
  pauseTaskIds?: string[];
  cancelTaskIds?: string[];
  reprioritize?: Array<{ plannedTaskId: string; priority: number; rationale?: string }>;
  redirectTasks?: Array<{ plannedTaskId: string; description?: string; role?: Parameters<ParallelTaskManager['redirectTask']>[1]['role'] }>;
  createTasks?: Array<Parameters<ParallelTaskManager['createTask']>[0]>;
  hypothesisUpdates?: Array<{ hypothesisId: string; confidence?: number; status?: 'OPEN' | 'SUPPORTED' | 'WEAKENED' | 'REJECTED'; statement?: string; title?: string }>;
}

const INVESTIGATION_AGENT_ROLES_SET: ReadonlySet<string> = new Set<string>(INVESTIGATION_AGENT_ROLES);

function isInvestigationAgentRole(value: string): boolean {
  return INVESTIGATION_AGENT_ROLES_SET.has(value);
}

export class RuntimeBackedInvestigationWorkerExecutor implements InvestigationWorkerExecutor {
  constructor(
    private readonly runtime: InvestigationSessionRuntime,
    private readonly investigationService: InvestigationService,
    private readonly options: Pick<RuntimeInvestigationOrchestratorOptions, 'pollIntervalMs' | 'workerAllowedTools' | 'getWorkspaceCwd'> = {}
  ) {}

  async execute(context: InvestigationWorkerContext): Promise<InvestigationWorkerResult> {
    // Workers always run inside the app's configured workspace. No hardcode,
    // no silent repo-root fallback: if no workspace is configured, refuse to
    // start the worker so the failure is visible to the operator.
    const workspaceCwd = this.options.getWorkspaceCwd?.() ?? null;
    if (!workspaceCwd) {
      throw new Error(
        `Investigation worker '${context.task.role}' cannot start: no workspace directory is configured. Set a working directory for the app before executing an investigation.`
      );
    }
    const cwd = workspaceCwd;
    const prompt = buildWorkerPrompt(context);
    const agent = getAgentDefinition(context.task.role);
    const agentAllowedCapabilities = agent.allowedTools.capabilities;
    const allowedTools = mergeAllowedTools(this.options.workerAllowedTools, agentAllowedCapabilities);
    const session = await this.runtime.startSession(
      `${context.task.role}: ${context.task.title}`,
      prompt,
      cwd,
      allowedTools,
      undefined,
      false
    );

    this.investigationService.linkSession(context.investigation.id, session.id, mapRoleToLinkRole(context.task.role));

    const abortHandler = () => {
      void this.runtime.stopSession(session.id);
    };
    if (context.signal.aborted) {
      abortHandler();
      throw new Error('cancelled');
    }
    context.signal.addEventListener('abort', abortHandler, { once: true });

    try {
      await waitForSessionCompletion(this.runtime, session.id, this.options.pollIntervalMs || 25, context.signal);
      const messages = this.runtime.getMessages(session.id);
      return parseWorkerMessages(messages);
    } finally {
      context.signal.removeEventListener('abort', abortHandler);
    }
  }
}

export class RuntimeInvestigationOrchestrator {
  private readonly planner: InvestigationPlanner;
  private readonly replanner: InvestigationReplanner;
  private readonly taskManager: ParallelTaskManager;

  constructor(
    private readonly investigationService: InvestigationService,
    runtime: InvestigationSessionRuntime,
    capabilities = new AgentCapabilityRegistry(),
    options: RuntimeInvestigationOrchestratorOptions = {}
  ) {
    this.planner = options.planner || new InvestigationPlanner(capabilities);
    this.replanner = new InvestigationReplanner(capabilities, this.planner);
    const executor = new RuntimeBackedInvestigationWorkerExecutor(runtime, investigationService, options);
    this.taskManager = new ParallelTaskManager(investigationService, executor, {
      scheduler: options.scheduler,
      maxRetries: options.maxRetries,
    });
  }

  createPlan(investigationId: string): InvestigationPlan {
    const investigation = this.investigationService.get(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);
    return this.planner.createPlan(investigation);
  }

  createReplan(investigationId: string) {
    const investigation = this.investigationService.get(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);
    return this.replanner.createReplan(investigation);
  }

  async executeInvestigation(investigationId: string): Promise<{ investigationId: string; plan: InvestigationPlan }> {
    const investigation = this.investigationService.get(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);
    const plan = investigation.status === 'REPLANNING' ? this.replanner.createReplan(investigation) : this.createPlan(investigationId);
    await this.taskManager.executePlan(investigationId, plan);
    return { investigationId, plan };
  }

  pauseTask(plannedTaskId: string, reason?: string): void {
    this.taskManager.pauseTask(plannedTaskId, reason);
  }

  resumeTask(plannedTaskId: string): void {
    this.taskManager.resumeTask(plannedTaskId);
  }

  cancelTask(plannedTaskId: string, reason?: string): void {
    this.taskManager.cancelTask(plannedTaskId, reason);
  }

  reprioritizeTask(plannedTaskId: string, priority: number, rationale?: string): void {
    this.taskManager.reprioritizeTask(plannedTaskId, priority, rationale);
  }

  createHumanDirectedTask(investigationId: string, input: Parameters<ParallelTaskManager['createTask']>[0]): void {
    const investigation = this.investigationService.get(investigationId);
    if (!investigation) throw new Error(`Investigation not found: ${investigationId}`);
    this.investigationService.addTask(investigationId, {
      title: input.title,
      description: input.description,
      type: 'AI',
      owner: input.role,
      priority: investigation.aiTasks.length + 1,
    });
    this.investigationService.recordEvent(investigationId, 'TASK_REPRIORITIZED', 'human', `Human-directed task queued: ${input.title}`, {
      plannedTaskId: input.id,
      role: input.role,
      kind: input.kind,
      autoExecuted: false,
    });
    this.taskManager.createTask(input);
  }

  applyHumanInterruption(
    investigationId: string,
    rawInput: ApplyHumanInterruptionInput
  ): { investigationId: string; updatedInvestigation: ReturnType<InvestigationService['get']>; operationalSummary: string } {
    const input = this.normalizeHumanInterruption(investigationId, rawInput);
    this.investigationService.addHumanInput(investigationId, input.instruction);
    for (const context of input.addContext || []) {
      this.investigationService.addNote(investigationId, context);
    }
    if (input.addPriority) {
      this.investigationService.addPriority(investigationId, input.addPriority);
    }
    if (input.redirectInvestigationTo) {
      this.investigationService.redirectInvestigation(investigationId, input.redirectInvestigationTo);
    }
    for (const evidenceId of input.ignoreEvidenceIds || []) {
      this.investigationService.ignoreFinding(investigationId, evidenceId, input.instruction);
    }
    for (const taskId of input.pauseTaskIds || []) {
      this.pauseTask(taskId, 'Paused by human interruption');
    }
    for (const taskId of input.cancelTaskIds || []) {
      this.cancelTask(taskId, 'Cancelled by human interruption');
    }
    for (const item of input.reprioritize || []) {
      this.reprioritizeTask(item.plannedTaskId, item.priority, item.rationale);
    }
    for (const item of input.redirectTasks || []) {
      this.redirectTask(item.plannedTaskId, { description: item.description, role: item.role });
    }
    for (const item of input.createTasks || []) {
      this.createHumanDirectedTask(investigationId, item);
    }
    for (const update of input.hypothesisUpdates || []) {
      this.investigationService.updateHypothesis(investigationId, update.hypothesisId, {
        confidence: update.confidence,
        status: update.status,
        statement: update.statement,
        title: update.title,
      });
    }

    const replan = this.replanner.createReplan(this.investigationService.get(investigationId)!);
    this.investigationService.recordEvent(investigationId, 'REPLAN_RECOMMENDED', 'system', 'Replan recommended after human interruption', {
      uncertaintySummary: replan.uncertainty.summary,
      uncertaintyReductionGoal: replan.nextBestWork.uncertaintyReductionGoal,
      recommendedTasks: replan.nextBestWork.recommendedTasks,
      autoExecuted: false,
      trigger: 'human_interruption',
    });

    const operationalSummary = [
      'Recorded human interruption.',
      (input.pauseTaskIds?.length || 0) > 0 ? `Paused ${input.pauseTaskIds?.length} task(s).` : null,
      (input.cancelTaskIds?.length || 0) > 0 ? `Cancelled ${input.cancelTaskIds?.length} task(s).` : null,
      (input.createTasks?.length || 0) > 0 ? `Queued ${input.createTasks?.length} new task(s).` : null,
      input.redirectInvestigationTo ? 'Marked investigation for replanning.' : null,
      input.addPriority ? 'Updated investigation priorities.' : null,
      (input.ignoreEvidenceIds?.length || 0) > 0 ? `Flagged ${input.ignoreEvidenceIds?.length} finding(s) to ignore.` : null,
    ].filter(Boolean).join(' ');

    const operationalRationale: OperationalRationale = buildHumanInterruptionRationale(input, operationalSummary);

    this.taskManager.explainOperationalAction(investigationId, operationalSummary, operationalRationale, {
      pauseTaskIds: input.pauseTaskIds || [],
      cancelTaskIds: input.cancelTaskIds || [],
      createdTaskIds: (input.createTasks || []).map((task) => task.id),
      redirectInvestigationTo: input.redirectInvestigationTo,
      addPriority: input.addPriority,
      ignoreEvidenceIds: input.ignoreEvidenceIds || [],
      autoExecuted: false,
    });

    return {
      investigationId,
      updatedInvestigation: this.investigationService.get(investigationId),
      operationalSummary,
    };
  }

  redirectTask(plannedTaskId: string, updates: { description?: string; role?: Parameters<ParallelTaskManager['redirectTask']>[1]['role'] }): void {
    this.taskManager.redirectTask(plannedTaskId, updates);
  }

  /**
   * Accepts both interruption payload shapes — the legacy batch form and the
   * single-action (kind-based) form sent by the workspace UI — validates it,
   * and reduces it to the batch form the orchestrator executes. Throws on
   * invalid input instead of silently coercing it.
   */
  private normalizeHumanInterruption(
    investigationId: string,
    raw: ApplyHumanInterruptionInput
  ): HumanInterruptionBatch {
    const trimText = (value: unknown): string => (typeof value === 'string' ? value.trim() : '');

    // Single-action (kind-based) shape from the workspace UI.
    if (typeof raw.kind === 'string' && raw.kind.length > 0) {
      const value = trimText(raw.value);
      const title = trimText(raw.title);
      const statement = trimText(raw.statement);
      const hypothesisId = trimText(raw.hypothesisId);

      switch (raw.kind) {
        case 'directive':
        case 'direction': {
          if (!value) throw new Error('Directive text is required');
          // 'direction' is an investigative redirect: it appends to
          // investigationDirections and marks the plan for replanning.
          if (raw.kind === 'direction') {
            this.investigationService.redirectInvestigation(investigationId, value);
          }
          return { instruction: value };
        }
        case 'note': {
          if (!value) throw new Error('Note text is required');
          return { instruction: value, addContext: [value] };
        }
        case 'suspicion': {
          if (!value) throw new Error('Suspicion text is required');
          this.investigationService.addHumanContext(investigationId, { suspicions: [value] });
          return { instruction: `Suspicion: ${value}` };
        }
        case 'constraint': {
          if (!value) throw new Error('Constraint text is required');
          this.investigationService.addConstraint(investigationId, value);
          return { instruction: `Constraint: ${value}` };
        }
        case 'hypothesis': {
          const hypothesisTitle = title || statement.slice(0, 80);
          const hypothesisStatement = statement || title;
          if (!hypothesisTitle || !hypothesisStatement) throw new Error('Hypothesis title and statement are required');
          this.investigationService.addHypothesis(investigationId, {
            title: hypothesisTitle,
            statement: hypothesisStatement,
            createdBy: 'human',
          });
          return { instruction: `Added hypothesis: ${hypothesisTitle}` };
        }
        case 'promote_hypothesis': {
          if (!hypothesisId) throw new Error('hypothesisId is required to promote a hypothesis');
          this.investigationService.promoteHypothesis(investigationId, hypothesisId);
          return { instruction: `Promoted hypothesis ${hypothesisId}` };
        }
        case 'reject_hypothesis': {
          if (!hypothesisId) throw new Error('hypothesisId is required to reject a hypothesis');
          this.investigationService.rejectHypothesis(investigationId, hypothesisId);
          return { instruction: `Rejected hypothesis ${hypothesisId}` };
        }
        case 'risk_tolerance': {
          if (value !== 'LOW' && value !== 'MEDIUM' && value !== 'HIGH') {
            throw new Error('Risk tolerance must be LOW, MEDIUM, or HIGH');
          }
          this.investigationService.addHumanContext(investigationId, { riskTolerance: value });
          return { instruction: `Set risk tolerance to ${value}` };
        }
        case 'reject_replan': {
          // Recorded as a human input; the actual plan decision is made by
          // the caller through investigation.plan / investigation.execute.
          if (!value && !statement) throw new Error('Rejection rationale is required');
          return { instruction: `Rejected replan recommendation: ${value || statement}` };
        }
        default:
          throw new Error(`Unsupported human interruption kind: ${raw.kind}`);
      }
    }

    // Legacy batch shape.
    const instruction = trimText(raw.instruction);
    if (!instruction) throw new Error('Human interruption instruction is required');

    const redirectTasks = (raw.redirectTasks || []).map((item) => {
      const plannedTaskId = trimText(item.plannedTaskId);
      if (!plannedTaskId) throw new Error('redirectTasks entries require plannedTaskId');
      const role = trimText(item.role);
      if (role && !isInvestigationAgentRole(role)) {
        throw new Error(`Unknown investigator role: ${role}`);
      }
      return {
        plannedTaskId,
        description: typeof item.description === 'string' ? item.description : undefined,
        role: (role || undefined) as InvestigationAgentRole | undefined,
      };
    });

    const createTasks = (raw.createTasks || []).map((task) => {
      if (!trimText(task.id) || !trimText(task.title)) {
        throw new Error('createTasks entries require id and title');
      }
      const role = trimText(task.role);
      if (role && !isInvestigationAgentRole(role)) {
        throw new Error(`Unknown investigator role: ${role}`);
      }
      return {
        ...task,
        dependsOn: task.dependsOn ?? [],
        canRunConcurrently: task.canRunConcurrently ?? true,
        role: (role || 'Evidence Analyst') as InvestigationAgentRole,
      };
    });

    return {
      instruction,
      addContext: raw.addContext,
      addPriority: raw.addPriority,
      redirectInvestigationTo: raw.redirectInvestigationTo,
      ignoreEvidenceIds: raw.ignoreEvidenceIds,
      pauseTaskIds: raw.pauseTaskIds,
      cancelTaskIds: raw.cancelTaskIds,
      reprioritize: raw.reprioritize,
      redirectTasks: redirectTasks.length > 0 ? redirectTasks : undefined,
      createTasks: createTasks.length > 0 ? createTasks : undefined,
      hypothesisUpdates: raw.hypothesisUpdates,
    };
  }
}

function buildWorkerPrompt(context: InvestigationWorkerContext): string {
  const hc = context.investigation.humanCapabilityContext;
  const agent = getAgentDefinition(context.task.role);
  const parts = [
    'You are an investigative worker in a shared cybersecurity investigation.',
    'Do not act like an independent chatbot. Work only on the assigned task.',
    'Use the investigation context provided below. Respect human constraints and known legitimate behavior.',
    '',
    `Investigation: ${context.investigation.title}`,
    `Objective: ${context.investigation.objective}`,
    `Status: ${context.investigation.status}`,
    `Assigned role: ${agent.role}`,
    `Assigned task: ${context.task.title}`,
    `Task description: ${context.task.description}`,
    '',
    `Role capability scope: ${agent.capabilityScope}`,
    `Role objective: ${agent.objective}`,
    `Allowed capability tools: ${agent.allowedTools.capabilities.join(', ') || '(none — read/think only)'}`,
    `Allowed tool categories: ${agent.allowedTools.toolCategories.join(', ')}`,
    `Forbidden actions: ${agent.allowedTools.forbidden.join(', ')}`,
    `Allowed finding types: ${agent.allowedFindingTypes.join(', ')}`,
    `Forbidden finding types: ${agent.forbiddenFindingTypes.join(', ') || '(none extra)'}`,
    `Confidence cap (neverAbove): ${agent.confidenceBehavior.neverAbove}`,
    '',
    '<role_system_prompt>',
    agent.systemPrompt,
    '</role_system_prompt>',
    '<role_negative_prompt>',
    agent.negativePrompt,
    '</role_negative_prompt>',
    '',
    'HALLUCINATION GUARD:',
    '- Distinguish OBSERVED (direct from a capability output or file), INFERRED (your analyst reasoning), and UNKNOWN (cannot be determined from available evidence).',
    '- Every evidence item must declare "classification": "OBSERVED" | "INFERRED" | "UNKNOWN".',
    '- Every evidence item MUST include provenance. Unsupported claims are rejected.',
    '- You may not emit CONCLUSION-type findings. Only humans promote to conclusions.',
    `- You may not use capabilities outside: ${agent.allowedTools.capabilities.join(', ') || '(none)'}.`,
    '- If you cannot cite a source, emit UNKNOWN.',
    '',
    'Human priorities:',
    ...(hc.priorities.length > 0 ? hc.priorities.map((item) => `- ${item.value}`) : ['- none']),
    'Human constraints:',
    ...(hc.constraints.length > 0 ? hc.constraints.map((item) => `- ${item.value}`) : ['- none']),
    'Known legitimate behavior:',
    ...(hc.knownLegitimateBehavior.length > 0
      ? hc.knownLegitimateBehavior.map((item) => `- ${item.value}`)
      : ['- none']),
    'Known abnormal behavior:',
    ...(hc.knownAbnormalBehavior.length > 0
      ? hc.knownAbnormalBehavior.map((item) => `- ${item.value}`)
      : ['- none']),
    'Open questions:',
    ...(context.investigation.openQuestions.length > 0
      ? context.investigation.openQuestions.map((item) => `- ${item}`)
      : ['- none']),
    '',
    'Return your result as JSON inside a fenced ```json block with this shape:',
    '{',
    '  "summary": string,',
    '  "evidence": [{',
    '    "classification": "OBSERVED" | "INFERRED" | "UNKNOWN",',
    '    "type"?: "OBSERVATION"|"INFERENCE"|"HYPOTHESIS",',
    '    "title": string,',
    '    "summary": string,',
    '    "content"?: string,',
    '    "kind": string,',
    '    "source"?: string,',
    '    "timestamp"?: number,',
    '    "investigator"?: string,',
    '    "relatedEntityIds"?: string[],',
    '    "confidence"?: number,',
    '    "hypothesisIds"?: string[],',
    '    "tags": string[],',
    '    "provenance"?: {',
    '      "method": "human_reported"|"agent_observed"|"tool_output"|"derived_analysis"|"imported",',
    '      "sourceType": "session_message"|"tool_execution"|"file"|"log"|"api"|"human_input"|"task_result"|"other",',
    '      "sourceId"?: string,',
    '      "sourceLabel"?: string,',
    '      "collectedBy"?: string,',
    '      "adapter"?: string,',
    '      "capability"?: string',
    '    }',
    '  }],',
    '  "inferences": [{ "statement": string, "basedOnEvidenceIds"?: string[], "confidence"?: number }],',
    '  "unknowns": [{ "question": string, "whatWouldResolve": string }],',
    '  "openQuestions": string[],',
    '  "notes": string[],',
    '  "hypothesisUpdates": [{ "hypothesisId"?: string, "title"?: string, "statement"?: string, "status"?: "OPEN"|"SUPPORTED"|"WEAKENED"|"REJECTED", "confidence"?: number }],',
    '  "operationalUpdate"?: {',
    '    "what": string,',
    '    "why": string,',
    '    "expectedValue": string,',
    '    "result"?: string,',
    '    "next"?: string',
    '  }',
    '}',
    'Use OBSERVATION for direct findings, INFERENCE for analyst reasoning, HYPOTHESIS for proposed explanations. Never emit CONCLUSION.',
    '',
    'Operational transparency: include an "operationalUpdate" object that explains what you just did, why, the value you expected to produce, the result you actually produced, and what should happen next. Use concise operational language. Do NOT expose private chain-of-thought, internal deliberation, or step-by-step reasoning — describe observable actions and their evidence-anchored rationale only. If you are mid-task and want to surface progress before completion, you may include only "what", "why", "expectedValue", and "next".',
  ];
  return parts.join('\n');
}

async function waitForSessionCompletion(
  runtime: InvestigationSessionRuntime,
  sessionId: string,
  pollIntervalMs: number,
  signal: AbortSignal
): Promise<void> {
  let completed = false;
  while (!completed) {
    if (signal.aborted) {
      throw new Error('cancelled');
    }
    const session = runtime.getSession(sessionId);
    if (!session || session.status === 'idle') {
      completed = true;
      continue;
    }
    if (session.status === 'error') {
      throw new Error('worker session failed');
    }
    await delay(pollIntervalMs);
  }
}

function parseWorkerMessages(messages: Message[]): InvestigationWorkerResult {
  const assistant = [...messages].reverse().find((message) => message.role === 'assistant');
  const text = assistant?.content
    .filter((block): block is Extract<Message['content'][number], { type: 'text' }> => block.type === 'text')
    .map((block) => block.text)
    .join('\n') || '';
  const parsed = extractJsonObject(text);
  if (!parsed) {
    return { summary: text || 'Worker completed without structured output' };
  }
  const validation = validateWorkerResultShape(parsed);
  if (!validation.ok) {
    const issueText = validation.issues
      .map((issue: { path: string; message: string }) => `${issue.path || '<root>'}: ${issue.message}`)
      .join('; ');
    return {
      summary:
        typeof parsed.summary === 'string' && parsed.summary.trim().length > 0
          ? parsed.summary
        : `Worker returned invalid structured output: ${issueText}`,
      notes: [`Worker structured output validation failed: ${issueText}`],
    };
  }
  const role = extractWorkerRole(messages);
  if (role) {
    const agentValidation = validateAgentOutput(role, parsed);
    if (!agentValidation.ok) {
      const issueText = agentValidation.issues
        .map((issue) => `${issue.path || '<root>'}: ${issue.message}`)
        .join('; ');
      return {
        summary: `Worker for ${role} produced disallowed output: ${issueText}`,
        notes: [
          `Agent output validation failed: ${issueText}`,
          `Classification counts: OBSERVED=${agentValidation.classificationCounts.OBSERVED}, INFERRED=${agentValidation.classificationCounts.INFERRED}, UNKNOWN=${agentValidation.classificationCounts.UNKNOWN}`,
        ],
      };
    }
  }
  return {
    summary: String(parsed.summary),
    evidence: Array.isArray(parsed.evidence) ? parsed.evidence : [],
    openQuestions: Array.isArray(parsed.openQuestions) ? parsed.openQuestions : [],
    notes: Array.isArray(parsed.notes) ? parsed.notes : [],
    hypothesisUpdates: Array.isArray(parsed.hypothesisUpdates) ? parsed.hypothesisUpdates : [],
    operationalUpdate: toOperationalRationale(parsed.operationalUpdate) ?? undefined,
  };
}

function extractWorkerRole(messages: Message[]): import('./parallel-investigation-engine').InvestigationAgentRole | null {
  const firstUser = messages.find((message) => message.role === 'user');
  if (!firstUser) return null;
  const title = firstUser.content
    .filter((block): block is Extract<Message['content'][number], { type: 'text' }> => block.type === 'text')
    .map((block) => block.text)
    .join(' ');
  const match = /^(Endpoint Investigator|Network Investigator|Identity Investigator|Threat Intelligence Investigator|Historical Investigator|Evidence Analyst|Research Investigator|Challenger):/.exec(title);
  return match ? (match[1] as import('./parallel-investigation-engine').InvestigationAgentRole) : null;
}

function extractJsonObject(text: string): Record<string, unknown> | null {
  const fenced = text.match(/```json\s*([\s\S]*?)```/i);
  const candidate = fenced?.[1] || text.trim();
  try {
    const parsed: unknown = JSON.parse(candidate);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function mapRoleToLinkRole(role: string): 'lead' | 'worker' | 'critic' {
  return role === 'Challenger' ? 'critic' : 'worker';
}

function mergeAllowedTools(global: string[] | undefined, agentCapabilities: string[]): string[] | undefined {
  if (!global && agentCapabilities.length === 0) return undefined;
  const set = new Set<string>(global || []);
  for (const capability of agentCapabilities) {
    set.add(`cyber_capability_execute:${capability}`);
  }
  return Array.from(set);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildHumanInterruptionRationale(
  input: {
    instruction: string;
    pauseTaskIds?: string[];
    cancelTaskIds?: string[];
    createTasks?: Array<{ id: string; title: string; description?: string }>;
    redirectInvestigationTo?: string;
    addPriority?: string;
    ignoreEvidenceIds?: string[];
  },
  summary: string
): OperationalRationale {
  const actionParts: string[] = [];
  if ((input.pauseTaskIds?.length || 0) > 0) actionParts.push(`pause ${input.pauseTaskIds?.length} task(s)`);
  if ((input.cancelTaskIds?.length || 0) > 0) actionParts.push(`cancel ${input.cancelTaskIds?.length} task(s)`);
  if ((input.createTasks?.length || 0) > 0) actionParts.push(`queue ${input.createTasks?.length} new task(s)`);
  if (input.ignoreEvidenceIds?.length) actionParts.push(`flag ${input.ignoreEvidenceIds.length} finding(s) to ignore`);
  if (input.addPriority) actionParts.push('update priorities');
  if (input.redirectInvestigationTo) actionParts.push('redirect the investigation');

  const what = actionParts.length > 0
    ? `Applying human interruption: ${actionParts.join(', ')}.`
    : 'Recording human interruption with no state changes.';

  const expectedValue = input.redirectInvestigationTo
    ? 'Realign the active plan with the new direction.'
    : input.pauseTaskIds?.length
      ? 'Pause selected work so the human can adjust course without losing state.'
      : 'Capture the human instruction and let it influence the next plan.';

  const next = input.redirectInvestigationTo
    ? 'A replan recommendation will follow.'
    : 'Workers will continue with the adjusted task set on the next scheduler tick.';

  return {
    what,
    why: input.instruction || 'Human supplied new instruction, context, or direction.',
    expectedValue,
    result: summary,
    next,
  };
}
