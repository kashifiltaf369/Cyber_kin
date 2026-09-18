import { describe, expect, it, vi } from 'vitest';
import { InvestigationReplanExtension } from '../src/main/investigation/investigation-replan-extension';
import type { DatabaseInstance, InvestigationEventRow, InvestigationRow, InvestigationSessionLinkRow } from '../src/main/db/database';
import { InvestigationService } from '../src/main/investigation/investigation-service';

function textFrom(result: { content?: Array<{ type: string; text?: string }> } | undefined): string {
  return result?.content?.[0]?.type === 'text' ? result.content[0].text || '' : '';
}

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

describe('InvestigationReplanExtension', () => {
  it('exposes uncertainty, cached recommendation, and next-best-work tools for linked sessions', async () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Case', objective: 'Determine whether service account X was misused' });

    let state = service.addHypothesis(created.id, {
      title: 'Credential theft',
      statement: 'The service account was abused by an attacker',
      confidence: 0.6,
      assumptions: ['Assume unusual host access is not routine'],
      unresolvedQuestions: ['Does the account normally authenticate from host Y?'],
      createdBy: 'human',
    });
    state = service.addHypothesis(created.id, {
      title: 'Routine maintenance',
      statement: 'The service account activity was part of normal maintenance',
      confidence: 0.58,
      assumptions: ['Scheduled maintenance may explain the behavior'],
      unresolvedQuestions: ['Was there an approved maintenance ticket?'],
      createdBy: 'human',
    });
    state = service.addHumanContext(created.id, {
      riskTolerance: 'LOW',
      knownLegitimateBehavior: ['Approved backup jobs use service accounts on weekends'],
    });
    state = service.addPriority(created.id, 'Determine whether service account X normally authenticates from host Y.');
    service.linkSession(created.id, 'session-1', 'worker');

    const extension = new InvestigationReplanExtension(service, (sessionId) =>
      service.getInvestigationIdBySessionId(sessionId)
    );

    const result = await extension.beforeSessionRun({
      session: {
        id: 'session-1',
        title: 'Worker',
        status: 'idle',
        mountedPaths: [],
        allowedTools: [],
        memoryEnabled: false,
        createdAt: 1,
        updatedAt: 1,
      },
      prompt: 'Read replan state',
      existingMessages: [],
      isColdStart: true,
    });

    expect(result.promptPrefix).toContain('uncertainty');
    expect(result.customTools).toHaveLength(1);

    const tool = result.customTools?.[0];
    const uncertainty = await tool?.execute('call-1', { queryType: 'uncertainty' }, undefined as never, undefined as never, { sessionManager: { getSessionId: () => 'session-1' } });
    expect(textFrom(uncertainty)).toContain('Current evidence');

    const cachedRecommendationBefore = await tool?.execute(
      'call-2',
      { queryType: 'cached_recommendation' },
      undefined as never,
      undefined as never,
      { sessionManager: { getSessionId: () => 'session-1' } }
    );
    expect(textFrom(cachedRecommendationBefore)).toContain('"hasRecommendation": false');
    expect(textFrom(cachedRecommendationBefore)).toContain('"source": "cached_event"');

    service.recordEvent(
      created.id,
      'REPLAN_RECOMMENDED',
      'system',
      'Replan recommended after evidence merge',
      {
        uncertaintySummary: 'Current evidence does not distinguish between hypothesis A and B.',
        uncertaintyReductionGoal: 'Determine whether service account X normally authenticates from host Y.',
        recommendedTasks: [
          {
            id: 'task-1',
            title: 'Check historical authentication baseline',
            role: 'Historical Investigator',
          },
        ],
        autoExecuted: false,
      }
    );

    const cachedRecommendationAfter = await tool?.execute(
      'call-3',
      { queryType: 'cached_recommendation' },
      undefined as never,
      undefined as never,
      { sessionManager: { getSessionId: () => 'session-1' } }
    );
    expect(textFrom(cachedRecommendationAfter)).toContain('"hasRecommendation": true');
    expect(textFrom(cachedRecommendationAfter)).toContain('Replan recommended after evidence merge');
    expect(textFrom(cachedRecommendationAfter)).toContain('Historical Investigator');
    expect(textFrom(cachedRecommendationAfter)).toContain('"autoExecuted": false');

    const nextBestWork = await tool?.execute('call-4', { queryType: 'next_best_work' }, undefined as never, undefined as never, { sessionManager: { getSessionId: () => 'session-1' } });
    expect(textFrom(nextBestWork)).toContain('advisoryOnly');
    expect(textFrom(nextBestWork)).toContain('recommendedTasks');
    expect(textFrom(nextBestWork)).toContain('"source": "computed"');

    const fullReplan = await tool?.execute('call-5', { queryType: 'full_replan' }, undefined as never, undefined as never, { sessionManager: { getSessionId: () => 'session-1' } });
    expect(textFrom(fullReplan)).toContain('uncertainty');
    expect(textFrom(fullReplan)).toContain('nextBestWork');
  });

  it('returns no replan tools when the session is not linked to an investigation', async () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const extension = new InvestigationReplanExtension(service, () => null);

    const result = await extension.beforeSessionRun({
      session: {
        id: 'unlinked',
        title: 'Standalone',
        status: 'idle',
        mountedPaths: [],
        allowedTools: [],
        memoryEnabled: false,
        createdAt: 1,
        updatedAt: 1,
      },
      prompt: 'Read replan state',
      existingMessages: [],
      isColdStart: true,
    });

    expect(result.promptPrefix).toBeUndefined();
    expect(result.customTools).toEqual([]);
  });
});
