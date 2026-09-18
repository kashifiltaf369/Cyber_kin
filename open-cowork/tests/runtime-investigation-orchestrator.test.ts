import { describe, expect, it, vi } from 'vitest';
import type {
  DatabaseInstance,
  InvestigationEventRow,
  InvestigationRow,
  InvestigationSessionLinkRow,
} from '../src/main/db/database';
import type { Message, Session } from '../src/renderer/types';
import { InvestigationService } from '../src/main/investigation/investigation-service';
import { RuntimeBackedInvestigationWorkerExecutor, RuntimeInvestigationOrchestrator } from '../src/main/investigation/runtime-investigation-orchestrator';
import type { PlannedInvestigationTask } from '../src/main/investigation/parallel-investigation-engine';

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

function createFakeRuntime() {
  const sessions = new Map<string, Session>();
  const messages = new Map<string, Message[]>();
  let counter = 0;

  return {
    runtime: {
      startSession: vi.fn(async (title: string, prompt: string) => {
        const id = `worker-${++counter}`;
        sessions.set(id, {
          id,
          title,
          status: 'running',
          mountedPaths: [],
          allowedTools: [],
          memoryEnabled: false,
          createdAt: Date.now(),
          updatedAt: Date.now(),
        });
        const payload = /Assigned role: ([^\n]+)/.exec(prompt)?.[1] || 'Unknown';
        messages.set(id, [
          {
            id: `msg-${id}`,
            sessionId: id,
            role: 'assistant',
            timestamp: Date.now(),
            content: [
              {
                type: 'text',
                text:
                  '```json\n' +
                  JSON.stringify({
                    summary: `${payload} summary`,
                    evidence: [
                      {
                        type: payload.includes('Evidence Analyst') ? 'INFERENCE' : 'OBSERVATION',
                        title: `${payload} evidence`,
                        summary: `Result from ${payload}`,
                        content: `Result from ${payload}`,
                        kind: 'note',
                        source: `${payload.toLowerCase().replace(/\s+/g, '-')}.json`,
                        provenance: {
                          method: payload.includes('Evidence Analyst') ? 'derived_analysis' : 'tool_output',
                          sourceType: 'task_result',
                          sourceLabel: `${payload} session output`,
                          collectedBy: payload,
                        },
                        tags: [payload.toLowerCase()],
                      },
                    ],
                    openQuestions: payload.includes('Identity') ? ['Was MFA bypassed?'] : [],
                    notes: payload.includes('Network') ? ['Network path reviewed'] : [],
                    hypothesisUpdates: [],
                  }) +
                  '\n```',
              },
            ],
          },
        ]);
        setTimeout(() => {
          const session = sessions.get(id);
          if (session) sessions.set(id, { ...session, status: 'idle', updatedAt: Date.now() });
        }, 5);
        return sessions.get(id)!;
      }),
      stopSession: vi.fn(async (sessionId: string) => {
        const session = sessions.get(sessionId);
        if (session) sessions.set(sessionId, { ...session, status: 'idle', updatedAt: Date.now() });
      }),
      getSession: vi.fn((sessionId: string) => sessions.get(sessionId) || null),
      getMessages: vi.fn((sessionId: string) => messages.get(sessionId) || []),
    },
  };
}

describe('Runtime investigation orchestrator', () => {
  it('parses structured worker output and links worker sessions to the investigation', async () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Case', objective: 'Investigate identity misuse and lateral movement' });
    const { runtime } = createFakeRuntime();
    const orchestrator = new RuntimeInvestigationOrchestrator(service, runtime, undefined, {
      pollIntervalMs: 1,
      getWorkspaceCwd: () => '/workspace',
    });

    const result = await orchestrator.executeInvestigation(created.id);
    const investigation = service.get(result.investigationId)!;

    expect(investigation.evidence.length).toBeGreaterThan(0);
    expect(investigation.evidence.find((item) => item.title === 'Identity Investigator evidence')?.type).toBe('OBSERVATION');
    expect(investigation.evidence.find((item) => item.title === 'Evidence Analyst evidence')?.type).toBe('INFERENCE');
    expect(investigation.evidence.find((item) => item.title === 'Identity Investigator evidence')?.provenance.sourceType).toBe('task_result');
    expect(investigation.openQuestions).toContain('Was MFA bypassed?');
    expect(investigation.humanCapabilityContext.notes.map((item) => item.value)).toContain('Network path reviewed');
    expect(investigation.activity.map((item) => item.type)).toContain('REPLAN_RECOMMENDED');
    const replanEvent = investigation.activity.find((item) => item.type === 'REPLAN_RECOMMENDED');
    expect(replanEvent?.data).toMatchObject({ autoExecuted: false });
    expect(runtime.startSession).toHaveBeenCalled();

    const firstWorkerSessionId = (runtime.startSession.mock.results[0]?.value && (await runtime.startSession.mock.results[0].value).id) || null;
    expect(firstWorkerSessionId).toBeTruthy();
    expect(service.getInvestigationIdBySessionId(firstWorkerSessionId!)).toBe(created.id);
  });

  it('records a validation note when worker structured output is malformed', async () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Case', objective: 'Investigate identity misuse' });

    const runtime = {
      startSession: vi.fn(async (title: string) => ({
        id: 'worker-invalid',
        title,
        status: 'idle' as const,
        mountedPaths: [],
        allowedTools: [],
        memoryEnabled: false,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      })),
      stopSession: vi.fn(async () => {
        /* noop */
      }),
      getSession: vi.fn(() => ({
        id: 'worker-invalid',
        title: 'worker',
        status: 'idle' as const,
        mountedPaths: [],
        allowedTools: [],
        memoryEnabled: false,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      })),
      getMessages: vi.fn(() => [
        {
          id: 'msg-invalid',
          sessionId: 'worker-invalid',
          role: 'assistant' as const,
          timestamp: Date.now(),
          content: [
            {
              type: 'text' as const,
              text: '```json\n' + JSON.stringify({ summary: '', evidence: [{ title: '', kind: 123 }] }) + '\n```',
            },
          ],
        },
      ]),
    };

    const orchestrator = new RuntimeInvestigationOrchestrator(service, runtime, undefined, {
      pollIntervalMs: 1,
      getWorkspaceCwd: () => '/workspace',
    });

    await orchestrator.executeInvestigation(created.id);
    const investigation = service.get(created.id)!;

    expect(investigation.evidence).toHaveLength(0);
    expect(investigation.humanCapabilityContext.notes.some((item) => item.value.includes('validation failed'))).toBe(true);
  });

  it('applies human interruption, redirect, and resume without losing investigation context', async () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Case', objective: 'Investigate suspicious domain and lateral movement' });
    const { runtime } = createFakeRuntime();
    const orchestrator = new RuntimeInvestigationOrchestrator(service, runtime, undefined, {
      pollIntervalMs: 1,
      getWorkspaceCwd: () => '/workspace',
    });

    const plannedTask: PlannedInvestigationTask = {
      id: 'planned-domain',
      title: 'Investigate suspicious domain',
      description: 'Review domain activity',
      role: 'Threat Intelligence Investigator',
      kind: 'research',
      dependsOn: [],
      canRunConcurrently: true,
      mergeStrategy: 'append_notes',
    };

    orchestrator.createHumanDirectedTask(created.id, plannedTask);
    const investigationBefore = service.get(created.id)!;
    const runtimeTaskId = investigationBefore.aiTasks[0]?.id;
    expect(runtimeTaskId).toBeTruthy();

    service.addEvidence(created.id, {
      type: 'OBSERVATION',
      title: 'Vendor domain observed',
      summary: 'The domain belongs to an approved vendor',
      content: 'Approved vendor domain',
      kind: 'note',
      source: 'human-note',
      timestamp: Date.now(),
      investigator: 'human',
      relatedEntityIds: [],
      confidence: 0.9,
      provenance: { method: 'human_reported', sourceType: 'human_input', collectedBy: 'human' },
      hypothesisIds: [],
      tags: ['vendor'],
    });
    const evidenceId = service.get(created.id)!.evidence[0]!.id;

    const interruption = orchestrator.applyHumanInterruption(created.id, {
      instruction: 'Stop investigating this domain. It belongs to our vendor. Focus on lateral movement.',
      addContext: ['Approved vendor domains should not consume more effort right now.'],
      addPriority: 'Focus on lateral movement.',
      redirectInvestigationTo: 'Focus on lateral movement and deprioritize vendor-owned domains.',
      ignoreEvidenceIds: [evidenceId],
      cancelTaskIds: ['planned-domain'],
      createTasks: [
        {
          id: 'planned-lateral',
          title: 'Investigate lateral movement',
          description: 'Review host-to-host movement and remote access paths',
          role: 'Network Investigator',
          kind: 'investigative',
          dependsOn: [],
          canRunConcurrently: true,
          mergeStrategy: 'append_evidence',
        },
      ],
    });

    expect(interruption.operationalSummary).toContain('Recorded human interruption');
    const updated = interruption.updatedInvestigation!;
    expect(updated.humanContext).toContain('Stop investigating this domain');
    expect(updated.humanCapabilityContext.priorities.map((item) => item.value)).toContain('Focus on lateral movement.');
    expect(updated.status).toBe('REPLANNING');
    expect(updated.evidence[0]?.analystAnnotations.some((item) => item.note.includes('Ignored finding'))).toBe(true);
    expect(updated.aiTasks.some((task) => task.title === 'Investigate lateral movement')).toBe(true);
    expect(updated.activity.map((item) => item.type)).toContain('AGENT_REDIRECTED');
    expect(updated.activity.map((item) => item.type)).toContain('TASK_IGNORED');
    expect(updated.activity.map((item) => item.type)).toContain('REPLAN_RECOMMENDED');
  });

  it('cancels a runtime worker session when the task signal aborts', async () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Case', objective: 'Investigate identity misuse' });

    let activeSessionId: string | null = null;
    const runtime = {
      startSession: vi.fn(async (title: string) => {
        activeSessionId = 'worker-cancel';
        return {
          id: activeSessionId,
          title,
          status: 'running' as const,
          mountedPaths: [],
          allowedTools: [],
          memoryEnabled: false,
          createdAt: Date.now(),
          updatedAt: Date.now(),
        };
      }),
      stopSession: vi.fn(async () => {
        /* noop */
      }),
      getSession: vi.fn(() => ({
        id: activeSessionId || 'worker-cancel',
        title: 'worker',
        status: 'running' as const,
        mountedPaths: [],
        allowedTools: [],
        memoryEnabled: false,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      })),
      getMessages: vi.fn(() => []),
    };

    const executor = new RuntimeBackedInvestigationWorkerExecutor(runtime, service, {
      pollIntervalMs: 1,
      getWorkspaceCwd: () => '/workspace',
    });
    const controller = new AbortController();
    const execution = executor.execute({
      investigation: service.get(created.id)!,
      task: {
        id: 'planned-1',
        title: 'Analyze identity activity',
        description: 'Check auth events',
        role: 'Identity Investigator',
        kind: 'investigative',
        dependsOn: [],
        canRunConcurrently: true,
        mergeStrategy: 'append_evidence',
      },
      attempt: 1,
      signal: controller.signal,
      readSharedState: () => service.get(created.id)!,
    });

    controller.abort();
    await expect(execution).rejects.toThrow('cancelled');
    expect(runtime.stopSession).toHaveBeenCalledWith('worker-cancel');
  });
});
