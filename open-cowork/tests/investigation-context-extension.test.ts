import { describe, expect, it, vi } from 'vitest';
import { InvestigationContextExtension } from '../src/main/investigation/investigation-context-extension';
import type { DatabaseInstance, InvestigationEventRow, InvestigationRow, InvestigationSessionLinkRow } from '../src/main/db/database';
import { InvestigationService } from '../src/main/investigation/investigation-service';

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

describe('InvestigationContextExtension', () => {
  it('injects planning context and exposes a read tool for linked sessions', async () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const investigation = service.create({
      title: 'Credential misuse',
      objective: 'Determine if account compromise occurred',
      humanContext: 'Tenant has frequent admin PowerShell usage',
    });
    service.addPriority(investigation.id, 'Investigate lateral movement first');
    service.addConstraint(investigation.id, 'Do not treat PowerShell alone as malicious');
    service.addHumanContext(investigation.id, {
      suspicions: ['Possible credential theft'],
      knownLegitimateBehavior: ['Daily PowerShell maintenance windows'],
      knownAbnormalBehavior: ['Interactive sign-ins outside support hours'],
      notes: ['Analyst believes VPN pivoting is plausible'],
      riskTolerance: 'LOW',
    });
    service.linkSession(investigation.id, 'session-1', 'lead');

    const extension = new InvestigationContextExtension(service, (sessionId) =>
      service.getInvestigationIdBySessionId(sessionId)
    );

    const result = await extension.beforeSessionRun({
      session: {
        id: 'session-1',
        title: 'Lead',
        status: 'idle',
        mountedPaths: [],
        allowedTools: [],
        memoryEnabled: false,
        createdAt: 1,
        updatedAt: 1,
      },
      prompt: 'Plan the next steps',
      existingMessages: [],
      isColdStart: true,
    });

    expect(result.promptPrefix).toContain('Investigation: Credential misuse');
    expect(result.promptPrefix).toContain('Priorities: Investigate lateral movement first');
    expect(result.promptPrefix).toContain('Constraints: Do not treat PowerShell alone as malicious');
    expect(result.promptPrefix).toContain('Risk tolerance: LOW');
    expect(result.customTools).toHaveLength(1);

    const tool = result.customTools?.[0];
    const full = await tool?.execute('call-1', {}, undefined as never, undefined as never, { sessionManager: { getSessionId: () => 'session-1' } });
    const fullText = full?.content?.[0]?.type === 'text' ? full.content[0].text : '';
    expect(fullText).toContain('Possible credential theft');
    expect(fullText).toContain('Daily PowerShell maintenance windows');

    const constraints = await tool?.execute(
      'call-2',
      { section: 'constraints' },
      undefined as never,
      undefined as never,
      { sessionManager: { getSessionId: () => 'session-1' } }
    );
    const constraintText = constraints?.content?.[0]?.type === 'text' ? constraints.content[0].text : '';
    expect(constraintText).toContain('Do not treat PowerShell alone as malicious');
  });

  it('returns no planning context when a session is not linked to an investigation', async () => {
    const { db } = makeDb();
    const service = new InvestigationService(db);
    const extension = new InvestigationContextExtension(service, () => null);

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
      prompt: 'Plan',
      existingMessages: [],
      isColdStart: true,
    });

    expect(result.promptPrefix).toBeUndefined();
    expect(result.customTools).toEqual([]);
  });
});
