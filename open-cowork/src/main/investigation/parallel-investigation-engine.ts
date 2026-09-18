import { v4 as uuidv4 } from 'uuid';
import type {
  Investigation,
  InvestigationEvidence,
  InvestigationTask,
  InvestigationEvent,
  OperationalRationale,
} from '../../shared/cyber/investigation-types';
import type { InvestigationService } from './investigation-service';
import { EvidenceIngestionService } from './evidence-ingestion-service';
import type { CompareHypothesesResult, ChallengerAssessment } from './hypothesis-service';
import { HypothesisService } from './hypothesis-service';
import { InvestigationReplanner } from './investigation-replanner';

export type InvestigationAgentRole =
  | 'Endpoint Investigator'
  | 'Network Investigator'
  | 'Identity Investigator'
  | 'Threat Intelligence Investigator'
  | 'Historical Investigator'
  | 'Evidence Analyst'
  | 'Research Investigator'
  | 'Challenger';

/** Runtime-checkable list of every investigator role (single source of truth). */
export const INVESTIGATION_AGENT_ROLES: readonly InvestigationAgentRole[] = [
  'Endpoint Investigator',
  'Network Investigator',
  'Identity Investigator',
  'Threat Intelligence Investigator',
  'Historical Investigator',
  'Evidence Analyst',
  'Research Investigator',
  'Challenger',
] as const;

export interface AgentCapabilityDefinition {
  role: InvestigationAgentRole;
  description: string;
  keywords: string[];
  canChallenge?: boolean;
  maxConcurrency?: number;
}

export interface PlannedInvestigationTask {
  id: string;
  title: string;
  description: string;
  role: InvestigationAgentRole;
  kind: 'investigative' | 'analysis' | 'challenge' | 'research';
  dependsOn: string[];
  canRunConcurrently: boolean;
  mergeStrategy: 'append_evidence' | 'update_hypothesis' | 'append_questions' | 'append_notes';
}

export interface InvestigationPlan {
  objective: string;
  summary: string;
  tasks: PlannedInvestigationTask[];
  createdAt: number;
  hypothesisSummary?: CompareHypothesesResult;
  challengerReview?: {
    investigationId: string;
    generatedAt: number;
    reviews: ChallengerAssessment[];
  };
}

export interface InvestigationWorkerResult {
  summary: string;
  evidence?: Array<
    Partial<
      Omit<
        InvestigationEvidence,
        'id' | 'investigationId' | 'collectedAt' | 'relationships' | 'analystAnnotations'
      >
    > &
      Pick<InvestigationEvidence, 'title' | 'kind'> & {
        collectedAt?: number;
        relationships?: InvestigationEvidence['relationships'];
        analystAnnotations?: InvestigationEvidence['analystAnnotations'];
      }
  >;
  openQuestions?: string[];
  notes?: string[];
  hypothesisUpdates?: Array<{
    hypothesisId?: string;
    title?: string;
    statement?: string;
    status?: 'OPEN' | 'SUPPORTED' | 'WEAKENED' | 'REJECTED';
    confidence?: number;
  }>;
  operationalUpdate?: OperationalRationale;
}

export interface InvestigationWorkerContext {
  investigation: Investigation;
  task: PlannedInvestigationTask;
  attempt: number;
  signal: AbortSignal;
  readSharedState: () => Investigation;
}

export interface InvestigationWorkerExecutor {
  execute(context: InvestigationWorkerContext): Promise<InvestigationWorkerResult>;
}

export interface ParallelTaskManagerOptions {
  scheduler?: TaskScheduler;
  maxRetries?: number;
  evidenceIngestionService?: EvidenceIngestionService;
  replanner?: InvestigationReplanner;
  autoRecommendReplan?: boolean;
}

export interface ManagedTaskState {
  task: PlannedInvestigationTask;
  runtimeTaskId: string;
  status: 'queued' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled';
  attempts: number;
  error?: string;
  startedAt?: number;
  endedAt?: number;
  priority: number;
  controller: AbortController;
}

export class AgentCapabilityRegistry {
  private readonly definitions = new Map<InvestigationAgentRole, AgentCapabilityDefinition>();

  constructor(definitions: AgentCapabilityDefinition[] = defaultCapabilityDefinitions()) {
    for (const definition of definitions) {
      this.definitions.set(definition.role, definition);
    }
  }

  get(role: InvestigationAgentRole): AgentCapabilityDefinition | null {
    return this.definitions.get(role) || null;
  }

  list(): AgentCapabilityDefinition[] {
    return Array.from(this.definitions.values());
  }

  selectRolesForInvestigation(investigation: Investigation): InvestigationAgentRole[] {
    const text = [
      investigation.title,
      investigation.objective,
      investigation.humanContext,
      ...investigation.humanCapabilityContext.priorities.map((item) => item.value),
      ...investigation.humanCapabilityContext.suspicions.map((item) => item.value),
      ...investigation.humanCapabilityContext.investigationDirections.map((item) => item.value),
      ...investigation.hypotheses.map((item) => `${item.title} ${item.statement}`),
    ]
      .join(' ')
      .toLowerCase();

    const matches = this.list()
      .filter((definition) => definition.keywords.some((keyword) => text.includes(keyword.toLowerCase())))
      .map((definition) => definition.role);

    const selected = new Set<InvestigationAgentRole>(matches);
    if (selected.size === 0) {
      selected.add('Evidence Analyst');
      selected.add('Research Investigator');
    }

    if (investigation.humanCapabilityContext.riskTolerance === 'LOW') {
      selected.add('Challenger');
    }

    return Array.from(selected);
  }
}

export class TaskDependencyGraph {
  private readonly taskMap = new Map<string, PlannedInvestigationTask>();

  constructor(tasks: PlannedInvestigationTask[]) {
    for (const task of tasks) {
      this.taskMap.set(task.id, task);
    }
  }

  getReady(completedTaskIds: Set<string>, runningTaskIds: Set<string>, failedTaskIds: Set<string>): PlannedInvestigationTask[] {
    return Array.from(this.taskMap.values()).filter((task) => {
      if (completedTaskIds.has(task.id) || runningTaskIds.has(task.id) || failedTaskIds.has(task.id)) return false;
      return task.dependsOn.every((dep) => completedTaskIds.has(dep));
    });
  }

  getBlockedByFailure(failedTaskIds: Set<string>): PlannedInvestigationTask[] {
    return Array.from(this.taskMap.values()).filter((task) => task.dependsOn.some((dep) => failedTaskIds.has(dep)));
  }

  hasTask(id: string): boolean {
    return this.taskMap.has(id);
  }
}

export class InvestigationPlanner {
  constructor(
    private readonly capabilities: AgentCapabilityRegistry,
    private readonly hypothesisService = new HypothesisService()
  ) {}

  createPlan(investigation: Investigation): InvestigationPlan {
    const roles = this.capabilities.selectRolesForInvestigation(investigation);
    const tasks: PlannedInvestigationTask[] = [];
    const objective = investigation.objective.trim();
    const lcObjective = objective.toLowerCase();
    const firstPriority = investigation.humanCapabilityContext.priorities[0]?.value;

    const hasIdentity = roles.includes('Identity Investigator');
    const hasEndpoint = roles.includes('Endpoint Investigator');
    const hasNetwork = roles.includes('Network Investigator');
    const hasThreatIntel = roles.includes('Threat Intelligence Investigator');
    const hasHistorical = roles.includes('Historical Investigator');
    const hasResearch = roles.includes('Research Investigator');
    const hasEvidenceAnalyst = roles.includes('Evidence Analyst');
    const hasChallenger = roles.includes('Challenger');
    const hypothesisSummary = investigation.hypotheses.length > 0
      ? this.hypothesisService.compare(investigation.hypotheses)
      : { ranked: [], leadingHypothesisId: null };
    const challengerReview = investigation.hypotheses.length > 0
      ? {
          investigationId: investigation.id,
          generatedAt: Date.now(),
          reviews: investigation.hypotheses.map((item) => this.hypothesisService.challenge(investigation, item.id)),
        }
      : undefined;
    const leadingHypothesis = hypothesisSummary.leadingHypothesisId
      ? investigation.hypotheses.find((item) => item.id === hypothesisSummary.leadingHypothesisId) || null
      : null;

    if (hasIdentity || /identity|credential|login|mfa|account|tenant/.test(lcObjective)) {
      tasks.push(createPlannedTask({
        title: 'Analyze identity activity',
        description: buildTaskDescription(
          'Review authentication, account access, and identity control-plane evidence.',
          firstPriority,
          leadingHypothesis?.statement
        ),
        role: 'Identity Investigator',
        kind: 'investigative',
        mergeStrategy: 'append_evidence',
      }));
    }

    if (hasEndpoint || /host|endpoint|powershell|process|registry|persistence/.test(lcObjective)) {
      tasks.push(createPlannedTask({
        title: 'Analyze endpoint activity',
        description: buildTaskDescription(
          'Review endpoint execution, process, and host evidence relevant to the investigation.',
          firstPriority,
          leadingHypothesis?.statement
        ),
        role: 'Endpoint Investigator',
        kind: 'investigative',
        mergeStrategy: 'append_evidence',
      }));
    }

    if (hasNetwork || /network|egress|beacon|dns|ip|lateral|traffic/.test(lcObjective) || containsPriority(investigation, 'lateral')) {
      tasks.push(createPlannedTask({
        title: 'Analyze network activity',
        description: buildTaskDescription(
          'Review network movement, lateral movement, DNS, and communications evidence.',
          firstPriority,
          leadingHypothesis?.statement
        ),
        role: 'Network Investigator',
        kind: 'investigative',
        mergeStrategy: 'append_evidence',
      }));
    }

    if (hasThreatIntel || /ioc|indicator|malware|campaign|threat intel|hash|domain/.test(lcObjective)) {
      tasks.push(createPlannedTask({
        title: 'Correlate threat intelligence',
        description: buildTaskDescription(
          'Correlate observed entities and evidence with threat intelligence and known malicious patterns.',
          firstPriority,
          leadingHypothesis?.statement
        ),
        role: 'Threat Intelligence Investigator',
        kind: 'research',
        mergeStrategy: 'append_evidence',
      }));
    }

    if (hasHistorical) {
      tasks.push(createPlannedTask({
        title: 'Compare with historical activity',
        description: buildTaskDescription(
          'Compare current investigation indicators against historical legitimate and abnormal behavior.',
          firstPriority,
          leadingHypothesis?.statement
        ),
        role: 'Historical Investigator',
        kind: 'research',
        mergeStrategy: 'append_notes',
      }));
    }

    if (hasResearch) {
      tasks.push(createPlannedTask({
        title: 'Research supporting context',
        description: buildTaskDescription(
          'Research techniques, tradecraft, and environmental context relevant to the investigation objective.',
          firstPriority,
          leadingHypothesis?.statement
        ),
        role: 'Research Investigator',
        kind: 'research',
        mergeStrategy: 'append_notes',
      }));
    }

    const synthesisDependencies = tasks.map((task) => task.id);
    if (hasEvidenceAnalyst || tasks.length > 1) {
      tasks.push(
        createPlannedTask({
          title: 'Synthesize evidence',
          description: buildTaskDescription(
            'Merge worker findings into a coherent evidence-backed summary with open questions.',
            firstPriority,
            leadingHypothesis?.statement
          ),
          role: 'Evidence Analyst',
          kind: 'analysis',
          dependsOn: synthesisDependencies,
          canRunConcurrently: false,
          mergeStrategy: 'append_questions',
        })
      );
    }

    if (hasChallenger) {
      tasks.push(
        createPlannedTask({
          title: 'Challenge current hypotheses',
          description: buildChallengeDescription(challengerReview?.reviews || [], leadingHypothesis?.statement),
          role: 'Challenger',
          kind: 'challenge',
          dependsOn: synthesisDependencies.length > 0 ? [synthesisDependencies.at(-1) as string] : [],
          canRunConcurrently: false,
          mergeStrategy: 'append_questions',
        })
      );
    }

    if (tasks.length === 0) {
      tasks.push(
        createPlannedTask({
          title: 'Perform initial evidence review',
          description: buildTaskDescription(
            'Perform an initial review of investigation objective, human context, and current evidence.',
            firstPriority,
            leadingHypothesis?.statement
          ),
          role: 'Evidence Analyst',
          kind: 'analysis',
          mergeStrategy: 'append_questions',
        })
      );
    }

    return {
      objective,
      summary: buildPlanSummary(objective, tasks.length, hypothesisSummary, challengerReview),
      tasks,
      createdAt: Date.now(),
      hypothesisSummary,
      challengerReview,
    };
  }
}

export class TaskScheduler {
  constructor(private readonly maxConcurrentTasks = 3) {}

  nextBatch(
    graph: TaskDependencyGraph,
    completedTaskIds: Set<string>,
    runningTaskIds: Set<string>,
    failedTaskIds: Set<string>
  ): PlannedInvestigationTask[] {
    const ready = graph.getReady(completedTaskIds, runningTaskIds, failedTaskIds);
    const capacity = Math.max(0, this.maxConcurrentTasks - runningTaskIds.size);
    return ready.slice(0, capacity);
  }
}

export class ParallelTaskManager {
  private readonly scheduler: TaskScheduler;
  private readonly maxRetries: number;
  private readonly evidenceIngestionService: EvidenceIngestionService;
  private readonly replanner: InvestigationReplanner;
  private readonly autoRecommendReplan: boolean;
  private readonly taskStates = new Map<string, ManagedTaskState>();
  private readonly runningPromises = new Map<string, Promise<void>>();
  private currentInvestigationId: string | null = null;

  constructor(
    private readonly investigationService: InvestigationService,
    private readonly executor: InvestigationWorkerExecutor,
    options: ParallelTaskManagerOptions = {}
  ) {
    this.scheduler = options.scheduler || new TaskScheduler();
    this.maxRetries = options.maxRetries ?? 1;
    this.evidenceIngestionService = options.evidenceIngestionService || new EvidenceIngestionService();
    this.replanner = options.replanner || new InvestigationReplanner();
    this.autoRecommendReplan = options.autoRecommendReplan ?? true;
  }

  getTaskState(taskId: string): ManagedTaskState | null {
    return this.taskStates.get(taskId) || null;
  }

  async executePlan(investigationId: string, plan: InvestigationPlan): Promise<Investigation> {
    this.currentInvestigationId = investigationId;
    this.investigationService.update(investigationId, { status: 'INVESTIGATING' });
    this.emitRuntimeEvent(investigationId, 'PLAN_CREATED', 'system', `Plan created with ${plan.tasks.length} tasks`, {
      taskCount: plan.tasks.length,
      summary: plan.summary,
      operationalUpdate: {
        what: `Generated ${plan.tasks.length} investigation task(s) from the leading hypothesis.`,
        why: 'Decompose the investigation objective into actionable work items assigned across investigative roles.',
        expectedValue: 'Determine the smallest next set of tasks that most reduces uncertainty against the active hypothesis.',
        result: `Plan contains ${plan.tasks.length} task(s).`,
        next: plan.tasks.length > 0 ? `Dispatch the first ready task(s) to their assigned investigators.` : undefined,
      },
    });

    for (const plannedTask of plan.tasks) {
      const investigation = this.investigationService.addTask(investigationId, {
        title: plannedTask.title,
        description: plannedTask.description,
        type: 'AI',
        owner: plannedTask.role,
      });
      const runtimeTask = investigation.aiTasks.at(-1) as InvestigationTask;
      this.taskStates.set(plannedTask.id, {
        task: plannedTask,
        runtimeTaskId: runtimeTask.id,
        status: 'queued',
        attempts: 0,
        priority: plan.tasks.length - plan.tasks.indexOf(plannedTask),
        controller: new AbortController(),
      });
    }

    const graph = new TaskDependencyGraph(plan.tasks);
    const completed = new Set<string>();
    const failed = new Set<string>();
    const cancelled = new Set<string>();
    const running = new Set<string>();

    while (completed.size + failed.size + cancelled.size < plan.tasks.length) {
      const batch = this.scheduler.nextBatch(graph, completed, running, failed);
      for (const task of batch) {
        const state = this.taskStates.get(task.id);
        if (!state || state.status === 'cancelled' || state.status === 'paused') continue;
        running.add(task.id);
        const promise = this.runTask(investigationId, state)
          .then((result) => {
            running.delete(task.id);
            if (result === 'completed') completed.add(task.id);
            else if (result === 'cancelled') cancelled.add(task.id);
            else failed.add(task.id);
          })
          .finally(() => {
            this.runningPromises.delete(task.id);
          });
        this.runningPromises.set(task.id, promise);
      }

      if (this.runningPromises.size === 0) {
        const blocked = graph.getBlockedByFailure(failed);
        for (const blockedTask of blocked) {
          if (!completed.has(blockedTask.id) && !failed.has(blockedTask.id) && !cancelled.has(blockedTask.id)) {
            this.cancelTask(blockedTask.id, 'Blocked by failed dependency');
            cancelled.add(blockedTask.id);
          }
        }
        break;
      }

      await Promise.race(this.runningPromises.values());
    }

    return this.investigationService.get(investigationId) as Investigation;
  }

  pauseTask(taskId: string, reason = 'Task paused by human'): void {
    const state = this.taskStates.get(taskId);
    if (!state || state.status === 'completed' || state.status === 'failed' || state.status === 'cancelled' || state.status === 'paused') return;
    state.status = 'paused';
    state.error = reason;
    state.controller.abort(reason);
    if (this.currentInvestigationId) {
      this.investigationService.updateTask(this.currentInvestigationId, state.runtimeTaskId, { status: 'PAUSED' as never });
      this.emitRuntimeEvent(this.currentInvestigationId, 'TASK_PAUSED', 'human', `Task paused: ${state.task.title}`, {
        taskId: state.runtimeTaskId,
        plannedTaskId: state.task.id,
        reason,
        status: 'PAUSED',
        operationalUpdate: {
          what: `Paused the ${state.task.role} task "${state.task.title}".`,
          why: reason || 'Paused by human interruption.',
          expectedValue: 'Stop in-flight work cleanly so the human can redirect or intervene without losing shared investigation state.',
          result: 'Task is paused and will not resume until a human action.',
          next: 'Wait for human to resume, redirect, or cancel the task.',
        },
      });
    }
  }

  resumeTask(taskId: string): void {
    const state = this.taskStates.get(taskId);
    if (!state || state.status !== 'paused') return;
    state.status = 'queued';
    state.error = undefined;
    state.controller = new AbortController();
    if (this.currentInvestigationId) {
      this.investigationService.updateTask(this.currentInvestigationId, state.runtimeTaskId, { status: 'CREATED' as never });
      this.emitRuntimeEvent(this.currentInvestigationId, 'TASK_RESUMED', 'human', `Task resumed: ${state.task.title}`, {
        taskId: state.runtimeTaskId,
        plannedTaskId: state.task.id,
        status: 'CREATED',
        operationalUpdate: {
          what: `Resumed the ${state.task.role} task "${state.task.title}".`,
          why: 'Human resumed a previously paused task.',
          expectedValue: 'Continue the task from where it was paused, preserving shared investigation state.',
          next: 'Worker will continue its previous line of investigation.',
        },
      });
    }
  }

  reprioritizeTask(taskId: string, priority: number, rationale?: string): void {
    const state = this.taskStates.get(taskId);
    if (!state) return;
    state.priority = priority;
    if (this.currentInvestigationId) {
      this.investigationService.updateTask(this.currentInvestigationId, state.runtimeTaskId, { priority });
      this.emitRuntimeEvent(this.currentInvestigationId, 'TASK_REPRIORITIZED', 'human', `Task reprioritized: ${state.task.title}`, {
        taskId: state.runtimeTaskId,
        plannedTaskId: state.task.id,
        priority,
        rationale,
        operationalUpdate: {
          what: `Changed priority of "${state.task.title}" to ${priority}.`,
          why: rationale || 'Human reprioritized the task.',
          expectedValue: 'Adjust scheduling order so higher-priority work runs first when capacity is available.',
          next: 'Scheduler will pick up the task according to its new priority on the next batch.',
        },
      });
    }
  }

  createTask(input: PlannedInvestigationTask): void {
    const investigationId = this.currentInvestigationId;
    if (!investigationId) return;
    const investigation = this.investigationService.addTask(investigationId, {
      title: input.title,
      description: input.description,
      type: 'AI',
      owner: input.role,
      priority: this.taskStates.size + 1,
    });
    const runtimeTask = investigation.aiTasks.at(-1) as InvestigationTask;
    this.taskStates.set(input.id, {
      task: input,
      runtimeTaskId: runtimeTask.id,
      status: 'queued',
      attempts: 0,
      priority: this.taskStates.size + 1,
      controller: new AbortController(),
    });
  }

  cancelTask(taskId: string, reason = 'Task cancelled'): void {
    const state = this.taskStates.get(taskId);
    if (!state || state.status === 'completed' || state.status === 'failed' || state.status === 'cancelled') return;
    state.status = 'cancelled';
    state.error = reason;
    state.controller.abort(reason);
    if (this.currentInvestigationId) {
      this.investigationService.updateTask(this.currentInvestigationId, state.runtimeTaskId, { status: 'CANCELLED' as never });
      this.emitRuntimeEvent(this.currentInvestigationId, 'TASK_UPDATED', 'system', `Task cancelled: ${state.task.title}`, {
        taskId: state.runtimeTaskId,
        plannedTaskId: state.task.id,
        reason,
        status: 'CANCELLED',
        operationalUpdate: {
          what: `Cancelled the ${state.task.role} task "${state.task.title}".`,
          why: reason || 'Task was cancelled.',
          expectedValue: 'Stop work on this task and unblock any tasks that were waiting on it.',
          result: 'Task is cancelled. Dependent tasks will be evaluated next.',
          next: 'Dependent tasks will either run or be cancelled based on the dependency graph.',
        },
      });
    }
  }

  redirectTask(taskId: string, updates: { description?: string; role?: InvestigationAgentRole }): void {
    const state = this.taskStates.get(taskId);
    if (!state) return;
    const nextTask: PlannedInvestigationTask = {
      ...state.task,
      ...(updates.description ? { description: updates.description } : {}),
      ...(updates.role ? { role: updates.role } : {}),
    };
    state.task = nextTask;
    if (this.currentInvestigationId) {
      this.investigationService.updateTask(this.currentInvestigationId, state.runtimeTaskId, {
        description: nextTask.description,
        owner: nextTask.role,
      });
      this.emitRuntimeEvent(
        this.currentInvestigationId,
        'AGENT_REDIRECTED',
        'human',
        `Task redirected: ${nextTask.title}`,
        {
          taskId: state.runtimeTaskId,
          plannedTaskId: state.task.id,
          role: nextTask.role,
          operationalUpdate: {
            what: `Redirected "${nextTask.title}" to ${nextTask.role}.`,
            why: 'Human redirected the worker to a different role or objective.',
            expectedValue: 'Realign the task with a more suitable investigative capability given current context.',
            next: 'Worker will be re-invoked with the updated role and description.',
          },
        }
      );
    }
  }

  explainOperationalChange(
    investigationId: string,
    summary: string,
    data?: Record<string, unknown>,
    rationale?: OperationalRationale
  ): void {
    if (rationale) {
      this.emitOperationalUpdate(investigationId, summary, data, rationale);
      return;
    }
    this.emitRuntimeEvent(investigationId, 'TASK_UPDATED', 'system', summary, data);
  }

  explainOperationalAction(
    investigationId: string,
    summary: string,
    rationale: OperationalRationale,
    data?: Record<string, unknown>
  ): void {
    this.emitOperationalUpdate(investigationId, summary, data, rationale);
  }

  private emitOperationalUpdate(
    investigationId: string,
    summary: string,
    data: Record<string, unknown> | undefined,
    rationale: OperationalRationale
  ): void {
    const payload: Record<string, unknown> = {
      ...(data || {}),
      operationalUpdate: rationale,
      rationale,
    };
    this.emitRuntimeEvent(investigationId, 'OPERATIONAL_UPDATE', 'system', summary, payload);
  }

  private async runTask(
    investigationId: string,
    state: ManagedTaskState
  ): Promise<'completed' | 'failed' | 'cancelled'> {
    state.attempts += 1;
    state.status = 'running';
    state.startedAt = Date.now();
    this.investigationService.updateTask(investigationId, state.runtimeTaskId, {
      status: 'STARTED',
      owner: state.task.role,
    });
    this.emitRuntimeEvent(investigationId, 'OPERATIONAL_UPDATE', 'system', `Task started: ${state.task.title}`, {
      taskId: state.runtimeTaskId,
      plannedTaskId: state.task.id,
      role: state.task.role,
      attempt: state.attempts,
      kind: state.task.kind,
      operationalUpdate: {
        what: `${state.task.role} is executing "${state.task.title}".`,
        why: state.task.description || 'Investigative worker is performing the assigned task.',
        expectedValue: 'Produce evidence, inferences, or hypothesis updates that reduce uncertainty in the active line of investigation.',
        next: 'Await worker output and merge any evidence back into the investigation.',
      },
    });

    try {
      const investigation = this.investigationService.get(investigationId) as Investigation;
      const result = await this.executor.execute({
        investigation,
        task: state.task,
        attempt: state.attempts,
        signal: state.controller.signal,
        readSharedState: () => this.investigationService.get(investigationId) as Investigation,
      });

      if (state.controller.signal.aborted) {
        state.status = 'cancelled';
        this.investigationService.updateTask(investigationId, state.runtimeTaskId, { status: 'CANCELLED' as never });
        return 'cancelled';
      }

      this.mergeResult(investigationId, state, result);
      state.status = 'completed';
      state.endedAt = Date.now();
      this.investigationService.updateTask(investigationId, state.runtimeTaskId, { status: 'COMPLETED' });
      this.emitRuntimeEvent(investigationId, 'OPERATIONAL_UPDATE', 'system', `Task completed: ${state.task.title}`, {
        taskId: state.runtimeTaskId,
        plannedTaskId: state.task.id,
        role: state.task.role,
        attempt: state.attempts,
        operationalUpdate: {
          what: `Worker for "${state.task.title}" finished and merged ${result.evidence?.length || 0} evidence item(s), ${result.openQuestions?.length || 0} open question(s), and ${result.hypothesisUpdates?.length || 0} hypothesis update(s).`,
          why: 'Task execution finished successfully.',
          expectedValue: 'Increase confidence in the active hypothesis or surface new leads worth investigating.',
          result: result.summary || 'Worker reported a structured summary with no narrative.',
          next: (result.evidence?.length || 0) > 0 || (result.openQuestions?.length || 0) > 0
            ? 'Review the new evidence and consider approving a replan.'
            : 'Continue with the next ready task in the plan.',
        },
      });
      return 'completed';
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (state.controller.signal.aborted) {
        state.status = 'cancelled';
        state.error = message;
        this.investigationService.updateTask(investigationId, state.runtimeTaskId, { status: 'CANCELLED' as never });
        return 'cancelled';
      }
      if (state.attempts <= this.maxRetries) {
        this.emitRuntimeEvent(investigationId, 'TASK_UPDATED', 'system', `Retrying task: ${state.task.title}`, {
          taskId: state.runtimeTaskId,
          plannedTaskId: state.task.id,
          attempt: state.attempts,
          error: message,
          operationalUpdate: {
            what: `Retrying "${state.task.title}" (attempt ${state.attempts}).`,
            why: `Previous attempt failed: ${message}`,
            expectedValue: 'Recover from a transient failure and complete the task on a fresh attempt.',
            result: 'Retry scheduled.',
            next: 'Re-invoke the worker with the same task context.',
          },
        });
        state.controller = new AbortController();
        state.status = 'queued';
        return this.runTask(investigationId, state);
      }
      state.status = 'failed';
      state.error = message;
      state.endedAt = Date.now();
      this.emitRuntimeEvent(investigationId, 'TASK_UPDATED', 'system', `Task failed: ${state.task.title}`, {
        taskId: state.runtimeTaskId,
        plannedTaskId: state.task.id,
        error: message,
        status: 'FAILED',
        operationalUpdate: {
          what: `Task "${state.task.title}" failed after ${state.attempts} attempt(s).`,
          why: `Worker reported an unrecoverable error: ${message}`,
          expectedValue: 'Surface the failure so a human can intervene and decide whether to retry, redirect, or replan.',
          result: 'Task marked as FAILED.',
          next: 'A human can retry, redirect, or trigger a replan. Dependent tasks are blocked.',
        },
      });
      return 'failed';
    }
  }

  private mergeResult(
    investigationId: string,
    state: ManagedTaskState,
    result: InvestigationWorkerResult
  ): void {
    for (const evidence of result.evidence || []) {
      this.investigationService.addEvidence(
        investigationId,
        this.evidenceIngestionService.normalizeWorkerEvidence(evidence, {
          investigationId,
          plannedTask: state.task,
          runtimeTask: { id: state.runtimeTaskId },
          attempt: state.attempts,
          workerSummary: result.summary,
        })
      );
    }
    for (const question of result.openQuestions || []) {
      this.investigationService.addOpenQuestion(investigationId, question);
    }
    for (const note of result.notes || []) {
      this.investigationService.addNote(investigationId, note);
    }
    for (const update of result.hypothesisUpdates || []) {
      if (update.hypothesisId) {
        this.investigationService.updateHypothesis(investigationId, update.hypothesisId, {
          title: update.title,
          statement: update.statement,
          status: update.status,
          confidence: update.confidence,
        });
      } else if (update.title && update.statement) {
        this.investigationService.addHypothesis(investigationId, {
          title: update.title,
          statement: update.statement,
          confidence: update.confidence,
        });
      }
    }
    this.emitRuntimeEvent(investigationId, 'TASK_UPDATED', 'agent', `Task merged into investigation: ${state.task.title}`, {
      taskId: state.runtimeTaskId,
      plannedTaskId: state.task.id,
      role: state.task.role,
      summary: result.summary,
    });

    if (result.operationalUpdate && result.operationalUpdate.what && result.operationalUpdate.why && result.operationalUpdate.expectedValue) {
      const rationale = result.operationalUpdate;
      this.emitOperationalUpdate(
        investigationId,
        `${state.task.role} reported: ${rationale.what}`,
        {
          taskId: state.runtimeTaskId,
          plannedTaskId: state.task.id,
          role: state.task.role,
          source: 'worker',
        },
        rationale
      );
    }

    if (this.autoRecommendReplan && this.shouldRecommendReplan(result, state.task)) {
      const latest = this.investigationService.get(investigationId) as Investigation;
      const replan = this.replanner.createReplan(latest);
      this.emitRuntimeEvent(
        investigationId,
        'REPLAN_RECOMMENDED',
        'system',
        `Replan recommended after task result: ${state.task.title}`,
        {
          triggerTaskId: state.runtimeTaskId,
          plannedTaskId: state.task.id,
          uncertaintySummary: replan.uncertainty.summary,
          uncertaintyReductionGoal: replan.nextBestWork.uncertaintyReductionGoal,
          recommendedTasks: replan.nextBestWork.recommendedTasks.map((task) => ({
            id: task.id,
            title: task.title,
            role: task.role,
            description: task.description,
            kind: task.kind,
          })),
          autoExecuted: false,
          operationalUpdate: {
            what: `Replanning after "${state.task.title}" produced ${replan.nextBestWork.recommendedTasks.length} recommended follow-up task(s).`,
            why: 'New evidence, open questions, or hypothesis updates were added by the worker.',
            expectedValue: replan.nextBestWork.uncertaintyReductionGoal,
            result: replan.uncertainty.summary,
            next: 'Wait for human to approve the replan. The recommended tasks will not run until approval.',
          },
        }
      );
    }
  }

  private shouldRecommendReplan(result: InvestigationWorkerResult, task: PlannedInvestigationTask): boolean {
    if ((result.evidence?.length || 0) > 0) return true;
    if ((result.openQuestions?.length || 0) > 0) return true;
    if ((result.hypothesisUpdates?.length || 0) > 0) return true;
    if (task.kind === 'challenge' && (result.notes?.length || 0) > 0) return true;
    return false;
  }

  private emitRuntimeEvent(
    investigationId: string,
    type: InvestigationEvent['type'],
    actor: InvestigationEvent['actor'],
    summary: string,
    data?: Record<string, unknown>
  ): void {
    const service = this.investigationService as InvestigationService & {
      recordEvent?: (
        id: string,
        eventType: InvestigationEvent['type'],
        actor: InvestigationEvent['actor'],
        summary: string,
        data?: Record<string, unknown>
      ) => void;
    };
    service.recordEvent?.(investigationId, type, actor, summary, data);
  }
}

function createPlannedTask(input: {
  title: string;
  description: string;
  role: InvestigationAgentRole;
  kind: PlannedInvestigationTask['kind'];
  dependsOn?: string[];
  canRunConcurrently?: boolean;
  mergeStrategy: PlannedInvestigationTask['mergeStrategy'];
}): PlannedInvestigationTask {
  return {
    id: uuidv4(),
    title: input.title,
    description: input.description,
    role: input.role,
    kind: input.kind,
    dependsOn: input.dependsOn || [],
    canRunConcurrently: input.canRunConcurrently ?? true,
    mergeStrategy: input.mergeStrategy,
  };
}

function buildTaskDescription(base: string, priority?: string, leadingHypothesisStatement?: string): string {
  const parts = [base.trim()];
  if (priority) parts.push(`Prioritize: ${priority}.`);
  if (leadingHypothesisStatement) {
    parts.push(`Evaluate against leading hypothesis: ${leadingHypothesisStatement}.`);
  }
  return parts.join(' ');
}

function buildChallengeDescription(
  reviews: ChallengerAssessment[],
  leadingHypothesisStatement?: string
): string {
  const parts = [
    'Act as a critical reviewer. Search for contradictory evidence, weak assumptions, alternative explanations, falsification conditions, and missing evidence.',
  ];
  if (leadingHypothesisStatement) {
    parts.push(`Primary hypothesis under challenge: ${leadingHypothesisStatement}.`);
  }
  const missingSignals = reviews.flatMap((item) => item.missingEvidence).slice(0, 3);
  if (missingSignals.length > 0) {
    parts.push(`Focus missing-evidence checks on: ${missingSignals.join(' | ')}.`);
  }
  return parts.join(' ');
}

function buildPlanSummary(
  objective: string,
  taskCount: number,
  hypothesisSummary: CompareHypothesesResult,
  challengerReview?: { reviews: ChallengerAssessment[] }
): string {
  const leading = hypothesisSummary.leadingHypothesisId
    ? hypothesisSummary.ranked.find((item) => item.hypothesis.id === hypothesisSummary.leadingHypothesisId)?.hypothesis
    : null;
  const contradictionCount = challengerReview?.reviews.reduce(
    (sum, review) => sum + review.contradictoryEvidence.length,
    0
  ) || 0;
  return [
    `Generated investigation plan with ${taskCount} task(s) for: ${objective}`,
    leading
      ? `Leading hypothesis: ${leading.title} (${leading.confidenceAssessment} confidence assessment).`
      : 'No explicit leading hypothesis yet.',
    challengerReview ? `Challenger flagged ${contradictionCount} contradictory evidence item(s) across hypotheses.` : null,
  ]
    .filter(Boolean)
    .join(' ');
}

function containsPriority(investigation: Investigation, term: string): boolean {
  return investigation.humanCapabilityContext.priorities.some((item) => item.value.toLowerCase().includes(term));
}



function defaultCapabilityDefinitions(): AgentCapabilityDefinition[] {
  return [
    {
      role: 'Endpoint Investigator',
      description: 'Investigates endpoint, host, process, and execution evidence.',
      keywords: ['powershell', 'endpoint', 'host', 'process', 'registry', 'persistence'],
      maxConcurrency: 2,
    },
    {
      role: 'Network Investigator',
      description: 'Investigates lateral movement, communications, DNS, and network evidence.',
      keywords: ['network', 'lateral', 'dns', 'traffic', 'beacon', 'egress', 'ip'],
      maxConcurrency: 2,
    },
    {
      role: 'Identity Investigator',
      description: 'Investigates identity, authentication, access, and account activity.',
      keywords: ['identity', 'login', 'credential', 'account', 'mfa', 'tenant', 'signin'],
      maxConcurrency: 2,
    },
    {
      role: 'Threat Intelligence Investigator',
      description: 'Correlates evidence with known campaigns, IOCs, and external intelligence.',
      keywords: ['threat', 'ioc', 'campaign', 'malware', 'hash', 'domain'],
      maxConcurrency: 1,
    },
    {
      role: 'Historical Investigator',
      description: 'Compares findings with historical baselines and environment behavior.',
      keywords: ['historical', 'baseline', 'legitimate', 'abnormal', 'usual'],
      maxConcurrency: 1,
    },
    {
      role: 'Evidence Analyst',
      description: 'Synthesizes evidence and identifies gaps or contradictions.',
      keywords: ['evidence', 'analyze', 'synthesize', 'summary'],
      maxConcurrency: 1,
    },
    {
      role: 'Research Investigator',
      description: 'Researches techniques, tradecraft, and contextual supporting information.',
      keywords: ['research', 'technique', 'tradecraft', 'context'],
      maxConcurrency: 1,
    },
    {
      role: 'Challenger',
      description: 'Challenges assumptions and proposes alternative explanations.',
      keywords: ['challenge', 'critic', 'alternative', 'assumption'],
      canChallenge: true,
      maxConcurrency: 1,
    },
  ];
}
