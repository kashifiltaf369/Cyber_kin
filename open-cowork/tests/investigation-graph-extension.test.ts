import { describe, expect, it, vi } from 'vitest';
import { InvestigationGraphExtension } from '../src/main/investigation/investigation-graph-extension';
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

describe('InvestigationGraphExtension', () => {
  it('exposes a graph query tool for linked sessions', async () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Credential misuse', objective: 'Determine account compromise' });

    let state = service.addEntity(created.id, { name: 'powershell.exe', type: 'process', summary: 'Proc' });
    state = service.addEntity(created.id, { name: 'Workstation-22', type: 'host', summary: 'Host' });
    const processId = state.entities.find((item) => item.name === 'powershell.exe')?.id as string;
    const hostId = state.entities.find((item) => item.name === 'Workstation-22')?.id as string;

    state = service.addEvidence(created.id, {
      type: 'OBSERVATION',
      title: 'Process execution',
      source: 'process telemetry',
      timestamp: 1_000,
      investigator: 'Endpoint Investigator',
      relatedEntityIds: [processId, hostId],
      content: 'powershell.exe executed on host',
      confidence: 0.95,
      provenance: { method: 'tool_output', sourceType: 'log' },
      hypothesisIds: [],
      kind: 'structured_record',
      summary: 'Execution observed',
      tags: [],
    });
    const evidenceId = state.evidence[0].id;

    state = service.addGraphRelationship(created.id, {
      type: 'EXECUTED',
      sourceEntityId: processId,
      targetEntityId: hostId,
      source: 'process telemetry',
      timestamp: 1_000,
      confidence: 0.95,
      evidenceIds: [evidenceId],
    });
    const relationshipId = state.graph.relationships[0].id;
    service.linkSession(created.id, 'session-1', 'worker');

    const extension = new InvestigationGraphExtension(service, (sessionId) =>
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
      prompt: 'Inspect graph',
      existingMessages: [],
      isColdStart: true,
    });

    expect(result.promptPrefix).toContain('Use the investigation graph');
    expect(result.customTools).toHaveLength(1);

    const tool = result.customTools?.[0];
    const overview = await tool?.execute('call-1', { queryType: 'overview' }, undefined as never, undefined as never, { sessionManager: { getSessionId: () => 'session-1' } });
    expect(textFrom(overview)).toContain('relationshipCount');

    const connected = await tool?.execute(
      'call-2',
      { queryType: 'connected_entities', entityId: processId, direction: 'outbound' },
      undefined as never,
      undefined as never,
      { sessionManager: { getSessionId: () => 'session-1' } }
    );
    expect(textFrom(connected)).toContain('Workstation-22');

    const evidence = await tool?.execute(
      'call-3',
      { queryType: 'evidence_for_relationship', relationshipId },
      undefined as never,
      undefined as never,
      { sessionManager: { getSessionId: () => 'session-1' } }
    );
    expect(textFrom(evidence)).toContain('Process execution');
  });

  it('returns no graph tools when the session is not linked to an investigation', async () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const extension = new InvestigationGraphExtension(service, () => null);

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
      prompt: 'Inspect graph',
      existingMessages: [],
      isColdStart: true,
    });

    expect(result.promptPrefix).toBeUndefined();
    expect(result.customTools).toEqual([]);
  });
});
