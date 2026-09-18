import { describe, expect, it, vi } from 'vitest';
import type {
  DatabaseInstance,
  InvestigationEventRow,
  InvestigationRow,
  InvestigationSessionLinkRow,
} from '../src/main/db/database';
import { InvestigationService } from '../src/main/investigation/investigation-service';
import {
  AgentCapabilityRegistry,
  InvestigationPlanner,
  ParallelTaskManager,
  TaskDependencyGraph,
  TaskScheduler,
  type InvestigationWorkerExecutor,
  type PlannedInvestigationTask,
} from '../src/main/investigation/parallel-investigation-engine';

function makeDb() {
  const investigations = new Map<string, InvestigationRow>();
  const events = new Map<string, InvestigationEventRow[]>();
  const links = new Map<string, InvestigationSessionLinkRow>();

  const db: DatabaseInstance = {
    raw: {} as never,
    investigations: {
      create: vi.fn((row: InvestigationRow) => investigations.set(row.id, { ...row })),
      update: vi.fn((id: string, updates: Partial<InvestigationRow>) => {
        const current = investigations.get(id);
        if (!current) return;
        investigations.set(id, { ...current, ...updates, updated_at: Date.now() });
      }),
      get: vi.fn((id: string) => investigations.get(id)),
      getAll: vi.fn(() => Array.from(investigations.values())),
      delete: vi.fn(),
    },
    investigationEvents: {
      create: vi.fn((row: InvestigationEventRow) => {
        const list = events.get(row.investigation_id) || [];
        list.push({ ...row });
        events.set(row.investigation_id, list);
      }),
      getByInvestigationId: vi.fn((id: string) => (events.get(id) || []).slice()),
      deleteByInvestigationId: vi.fn(),
    },
    investigationSessionLinks: {
      link: vi.fn((investigationId: string, sessionId: string, role: string) => {
        links.set(sessionId, { investigation_id: investigationId, session_id: sessionId, role, created_at: Date.now() });
      }),
      getInvestigationIdBySessionId: vi.fn((sessionId: string) => links.get(sessionId)?.investigation_id ?? null),
      getSessionLinksByInvestigationId: vi.fn((investigationId: string) =>
        Array.from(links.values()).filter((item) => item.investigation_id === investigationId)
      ),
      deleteBySessionId: vi.fn((sessionId: string) => {
        links.delete(sessionId);
      }),
    },
    sessions: {} as never,
    messages: {} as never,
    traceSteps: {} as never,
    scheduledTasks: {} as never,
    prepare: vi.fn() as never,
    exec: vi.fn(),
    pragma: vi.fn(),
    close: vi.fn(),
  };

  return { db };
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe('Parallel Investigation Engine', () => {
  it('creates a plan based on investigation objective, hypotheses, and human context', () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const investigation = service.create({
      title: 'Credential theft case',
      objective: 'Investigate credential theft and lateral movement across hosts',
      humanContext: 'PowerShell is heavily used in this environment',
    });
    service.addPriority(investigation.id, 'Investigate lateral movement first');
    service.addConstraint(investigation.id, 'Do not treat PowerShell alone as malicious');
    service.addHumanContext(investigation.id, {
      suspicions: ['Possible credential theft'],
      riskTolerance: 'LOW',
      knownLegitimateBehavior: ['Routine admin PowerShell during approved maintenance'],
    });
    service.addHypothesis(investigation.id, {
      title: 'Credential theft',
      statement: 'Stolen credentials were used to access internal systems',
      confidence: 0.6,
      assumptions: ['Assume unusual sign-ins indicate compromise'],
      unresolvedQuestions: ['Was MFA bypassed?'],
      createdBy: 'human',
    });
    service.addHypothesis(investigation.id, {
      title: 'Administrative maintenance',
      statement: 'Observed actions were part of planned administrator maintenance',
      confidence: 0.45,
      assumptions: ['A maintenance window may explain the behavior'],
      unresolvedQuestions: ['Is there an approved change ticket?'],
      createdBy: 'human',
    });

    const planner = new InvestigationPlanner(new AgentCapabilityRegistry());
    const plan = planner.createPlan(service.get(investigation.id)!);

    expect(plan.tasks.length).toBeGreaterThan(2);
    expect(plan.tasks.some((task) => task.role === 'Identity Investigator')).toBe(true);
    expect(plan.tasks.some((task) => task.role === 'Network Investigator')).toBe(true);
    expect(plan.tasks.some((task) => task.role === 'Challenger')).toBe(true);
    expect(plan.tasks.some((task) => task.dependsOn.length > 0)).toBe(true);
    expect(plan.hypothesisSummary?.ranked).toHaveLength(2);
    expect(plan.summary).toContain('Leading hypothesis');
    expect(plan.challengerReview?.reviews.length).toBe(2);
    expect(plan.tasks.some((task) => task.description.includes('Evaluate against leading hypothesis'))).toBe(true);
    expect(plan.tasks.find((task) => task.role === 'Challenger')?.description).toContain('Primary hypothesis under challenge');
  });

  it('schedules dependency-free tasks concurrently and merges results into shared investigation state', async () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({
      title: 'Investigation',
      objective: 'Investigate identity misuse and lateral movement',
    });

    const planner = new InvestigationPlanner(new AgentCapabilityRegistry());
    const plan = planner.createPlan(service.get(created.id)!);

    const identityGate = deferred<void>();
    const networkGate = deferred<void>();
    const starts: string[] = [];
    const executor: InvestigationWorkerExecutor = {
      execute: vi.fn(async ({ task }) => {
        starts.push(task.role);
        if (task.role === 'Identity Investigator') {
          await identityGate.promise;
          return {
            summary: 'Identity findings',
            evidence: [{ title: 'Suspicious sign-in', summary: 'Impossible travel', kind: 'log_excerpt', source: 'idp.log', tags: ['identity'] }],
            openQuestions: ['Was MFA bypassed?'],
          };
        }
        if (task.role === 'Network Investigator') {
          await networkGate.promise;
          return {
            summary: 'Network findings',
            evidence: [{ title: 'Remote SMB access', summary: 'Host-to-host movement', kind: 'structured_record', source: 'netflow.json', tags: ['network'] }],
            notes: ['Network path suggests lateral movement'],
          };
        }
        return { summary: `Completed ${task.role}` };
      }),
    };

    const manager = new ParallelTaskManager(service, executor, {
      scheduler: new TaskScheduler(2),
      maxRetries: 0,
    });

    const running = manager.executePlan(created.id, plan);
    await Promise.resolve();
    await Promise.resolve();

    expect(starts).toEqual(expect.arrayContaining(['Identity Investigator', 'Network Investigator']));

    identityGate.resolve();
    networkGate.resolve();
    const finalInvestigation = await running;

    expect(finalInvestigation.status).toBe('INVESTIGATING');
    expect(finalInvestigation.evidence.map((item) => item.title)).toContain('Suspicious sign-in');
    expect(finalInvestigation.evidence.map((item) => item.title)).toContain('Remote SMB access');
    expect(finalInvestigation.openQuestions).toContain('Was MFA bypassed?');
    expect(finalInvestigation.humanCapabilityContext.notes.map((item) => item.value)).toContain(
      'Network path suggests lateral movement'
    );
    expect(finalInvestigation.evidence.find((item) => item.title === 'Suspicious sign-in')?.type).toBe('OBSERVATION');
    expect(finalInvestigation.evidence.find((item) => item.title === 'Suspicious sign-in')?.provenance.sourceType).toBe('task_result');
    expect(finalInvestigation.evidence.find((item) => item.title === 'Suspicious sign-in')?.supportingTaskId).toBeTruthy();
    expect(finalInvestigation.activity.map((item) => item.type)).toContain('PLAN_CREATED');
    expect(finalInvestigation.activity.map((item) => item.type)).toContain('TASK_COMPLETED');
    expect(finalInvestigation.activity.map((item) => item.type)).toContain('REPLAN_RECOMMENDED');
  });

  it('retries failed tasks and eventually succeeds', async () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Investigation', objective: 'Investigate identity misuse' });
    const planner = new InvestigationPlanner(new AgentCapabilityRegistry());
    const plan = planner.createPlan(service.get(created.id)!);

    let attempts = 0;
    const executor: InvestigationWorkerExecutor = {
      execute: vi.fn(async ({ task }) => {
        if (task.role === 'Identity Investigator') {
          attempts += 1;
          if (attempts === 1) throw new Error('transient failure');
          return {
            summary: 'Recovered on retry',
            evidence: [{ title: 'Recovered evidence', summary: 'Retry succeeded', kind: 'note', tags: ['retry'] }],
          };
        }
        return { summary: `Completed ${task.role}` };
      }),
    };

    const manager = new ParallelTaskManager(service, executor, { maxRetries: 1, scheduler: new TaskScheduler(1) });
    const finalInvestigation = await manager.executePlan(created.id, plan);

    expect(attempts).toBe(2);
    expect(finalInvestigation.evidence.map((item) => item.title)).toContain('Recovered evidence');
    expect(finalInvestigation.evidence.find((item) => item.title === 'Recovered evidence')?.provenance.details).toMatchObject({
      taskKind: 'investigative',
      attempt: 2,
    });
    expect(finalInvestigation.activity.some((item) => item.summary.includes('Retrying task'))).toBe(true);
  });

  it('supports pause, resume, reprioritize, and cancellation of running tasks', async () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Investigation', objective: 'Investigate identity misuse' });

    const blockingTask: PlannedInvestigationTask = {
      id: 'task-1',
      title: 'Analyze identity activity',
      description: 'Check sign-ins',
      role: 'Identity Investigator',
      kind: 'investigative',
      dependsOn: [],
      canRunConcurrently: true,
      mergeStrategy: 'append_evidence',
    };

    const executor: InvestigationWorkerExecutor = {
      execute: vi.fn(({ signal }) =>
        new Promise((resolve, reject) => {
          signal.addEventListener('abort', () => reject(new Error('cancelled')));
        })
      ),
    };

    const manager = new ParallelTaskManager(service, executor, { maxRetries: 0, scheduler: new TaskScheduler(1) });
    const runPromise = manager.executePlan(created.id, {
      objective: created.objective,
      summary: 'Single blocking task',
      tasks: [blockingTask],
      createdAt: Date.now(),
    });

    await Promise.resolve();
    manager.pauseTask('task-1', 'Human paused task');
    expect(manager.getTaskState('task-1')?.status).toBe('paused');

    manager.resumeTask('task-1');
    expect(manager.getTaskState('task-1')?.status).toBe('queued');

    manager.reprioritizeTask('task-1', 99, 'Human wants deeper investigation');
    expect(manager.getTaskState('task-1')?.priority).toBe(99);

    manager.cancelTask('task-1', 'Human cancelled task');
    const finalInvestigation = await runPromise;

    expect(manager.getTaskState('task-1')?.status).toBe('cancelled');
    expect(finalInvestigation.aiTasks[0]?.status).toBe('CANCELLED');
    expect(finalInvestigation.activity.map((item) => item.type)).toContain('TASK_PAUSED');
    expect(finalInvestigation.activity.map((item) => item.type)).toContain('TASK_RESUMED');
    expect(finalInvestigation.activity.map((item) => item.type)).toContain('TASK_REPRIORITIZED');
  });

  it('blocks dependent tasks after upstream failure', async () => {
    const graph = new TaskDependencyGraph([
      {
        id: 'a',
        title: 'A',
        description: 'A',
        role: 'Identity Investigator',
        kind: 'investigative',
        dependsOn: [],
        canRunConcurrently: true,
        mergeStrategy: 'append_evidence',
      },
      {
        id: 'b',
        title: 'B',
        description: 'B',
        role: 'Evidence Analyst',
        kind: 'analysis',
        dependsOn: ['a'],
        canRunConcurrently: false,
        mergeStrategy: 'append_questions',
      },
    ]);

    const readyInitially = graph.getReady(new Set(), new Set(), new Set());
    expect(readyInitially.map((task) => task.id)).toEqual(['a']);

    const blocked = graph.getBlockedByFailure(new Set(['a']));
    expect(blocked.map((task) => task.id)).toContain('b');
  });
});
