import { describe, expect, it, vi } from 'vitest';
import { InvestigationCyberAuditExtension } from '../src/main/investigation/investigation-cyber-audit-extension';
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

describe('InvestigationCyberAuditExtension', () => {
  it('exposes cyber audit queries for linked sessions', async () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const created = service.create({ title: 'Case', objective: 'Investigate suspicious file access' });
    service.linkSession(created.id, 'session-1', 'worker');
    service.recordEvent(created.id, 'CYBER_ACTION_AUDITED', 'agent', 'Cyber action denied: delete_file', {
      capabilityName: 'delete_file',
      actionCategory: 'DESTRUCTIVE_ACTION',
      approvalState: 'REQUIRES_EXPLICIT_HUMAN_APPROVAL',
      target: 'artifact.bin',
      result: { status: 'denied', summary: 'Requires explicit human approval' },
    });
    service.recordEvent(created.id, 'CYBER_ACTION_AUDITED', 'agent', 'Cyber action executed: inspect_file', {
      capabilityName: 'inspect_file',
      actionCategory: 'READ_ONLY',
      approvalState: 'NOT_REQUIRED',
      target: 'artifact.bin',
      result: { status: 'executed', summary: 'Inspected artifact' },
    });

    const extension = new InvestigationCyberAuditExtension(service, (sessionId) =>
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
      prompt: 'Review cyber audit trail',
      existingMessages: [],
      isColdStart: true,
    });

    expect(result.promptPrefix).toContain('cyber audit history');
    expect(result.customTools).toHaveLength(1);

    const tool = result.customTools?.[0];
    const recent = await tool?.execute('call-1', { mode: 'recent', limit: 5 }, undefined as never, undefined as never, {
      sessionId: 'session-1',
    });
    expect(textFrom(recent)).toContain('CYBER_ACTION_AUDITED');
    expect(textFrom(recent)).toContain('inspect_file');

    const denied = await tool?.execute('call-2', { mode: 'denied' }, undefined as never, undefined as never, {
      sessionId: 'session-1',
    });
    expect(textFrom(denied)).toContain('DESTRUCTIVE_ACTION');
    expect(textFrom(denied)).toContain('Requires explicit human approval');

    const summary = await tool?.execute('call-3', { mode: 'summary' }, undefined as never, undefined as never, {
      sessionId: 'session-1',
    });
    expect(textFrom(summary)).toContain('totalAuditEvents');
    expect(textFrom(summary)).toContain('explicitApprovalRequiredCount');

    const serviceSummary = service.summarizeCyberAuditEvents(created.id, 5);
    expect(serviceSummary.totalAuditEvents).toBe(2);
    expect(serviceSummary.explicitApprovalRequiredCount).toBe(1);
    expect(service.getCyberAuditEvents(created.id, { mode: 'high_risk', limit: 10 })).toHaveLength(1);
  });

  it('returns no cyber audit tools when the session is not linked to an investigation', async () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const extension = new InvestigationCyberAuditExtension(service, () => null);

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
      prompt: 'Review cyber audit trail',
      existingMessages: [],
      isColdStart: true,
    });

    expect(result.promptPrefix).toBeUndefined();
    expect(result.customTools).toEqual([]);
  });
});
