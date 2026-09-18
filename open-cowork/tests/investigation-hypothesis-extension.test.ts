import { describe, expect, it, vi } from 'vitest';
import { InvestigationHypothesisExtension } from '../src/main/investigation/investigation-hypothesis-extension';
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

describe('InvestigationHypothesisExtension', () => {
  it('exposes hypothesis comparison and challenger tools for linked sessions', async () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Case', objective: 'Obj' });

    let state = service.addHypothesis(created.id, {
      title: 'Credential theft',
      statement: 'Stolen credentials were used',
      confidence: 0.55,
      assumptions: ['Assume impossible travel indicates compromise'],
      unresolvedQuestions: ['Was MFA challenged?'],
      createdBy: 'human',
    });
    state = service.addHypothesis(created.id, {
      title: 'Administrative maintenance',
      statement: 'Observed activity is normal admin work',
      confidence: 0.45,
      assumptions: ['Known maintenance tasks may explain the activity'],
      unresolvedQuestions: ['Was there a maintenance ticket?'],
      createdBy: 'human',
    });

    const theftId = state.hypotheses.find((item) => item.title === 'Credential theft')?.id as string;
    state = service.addEvidence(created.id, {
      type: 'OBSERVATION',
      title: 'Maintenance ticket exists',
      source: 'change-record',
      timestamp: 100,
      investigator: 'Historical Investigator',
      relatedEntityIds: [],
      content: 'A change ticket exists for routine admin work.',
      confidence: 0.8,
      provenance: { method: 'imported', sourceType: 'file' },
      hypothesisIds: [],
      kind: 'note',
      summary: 'Maintenance ticket found',
      tags: [],
    });
    const evidenceId = state.evidence[0].id;
    service.addContradictingEvidence(created.id, theftId, evidenceId, 'Documented maintenance weakens compromise claim', 'agent');
    service.linkSession(created.id, 'session-1', 'worker');

    const extension = new InvestigationHypothesisExtension(service, (sessionId) =>
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
      prompt: 'Assess hypotheses',
      existingMessages: [],
      isColdStart: true,
    });

    expect(result.promptPrefix).toContain('competing explanations');
    expect(result.customTools).toHaveLength(1);

    const tool = result.customTools?.[0];
    const comparison = await tool?.execute('call-1', { queryType: 'compare' }, undefined as never, undefined as never, { sessionManager: { getSessionId: () => 'session-1' } });
    expect(textFrom(comparison)).toContain('leadingHypothesisId');

    const challenge = await tool?.execute('call-2', { queryType: 'challenge', hypothesisId: theftId }, undefined as never, undefined as never, { sessionManager: { getSessionId: () => 'session-1' } });
    expect(textFrom(challenge)).toContain('contradictoryEvidence');

    const list = await tool?.execute('call-3', { queryType: 'list' }, undefined as never, undefined as never, { sessionManager: { getSessionId: () => 'session-1' } });
    expect(textFrom(list)).toContain('Credential theft');
  });

  it('returns no hypothesis tools when the session is not linked to an investigation', async () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const extension = new InvestigationHypothesisExtension(service, () => null);

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
      prompt: 'Assess hypotheses',
      existingMessages: [],
      isColdStart: true,
    });

    expect(result.promptPrefix).toBeUndefined();
    expect(result.customTools).toEqual([]);
  });
});
