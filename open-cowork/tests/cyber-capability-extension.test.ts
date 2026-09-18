import { describe, expect, it, vi } from 'vitest';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { CyberCapabilityExtension } from '../src/main/cyber/cyber-capability-extension';
import { CyberCapabilityRegistry, type CyberCapabilityDefinition } from '../src/main/cyber/cyber-capability-registry';
import { CyberActionAuditTrail, CyberPermissionPolicy } from '../src/main/cyber/cyber-permission-policy';
import { InvestigationService } from '../src/main/investigation/investigation-service';
import type { DatabaseInstance, InvestigationEventRow, InvestigationRow, InvestigationSessionLinkRow } from '../src/main/db/database';

function textFrom(result: Awaited<ReturnType<NonNullable<ReturnType<CyberCapabilityExtension['beforeSessionRun']>['customTools']>[number]['execute']>>) {
  return result?.content?.[0]?.type === 'text' ? result.content[0].text : '';
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

describe('CyberCapabilityExtension', () => {
  it('exposes discovery and execution tools with capability-oriented guidance', async () => {
    const registry = new CyberCapabilityRegistry();
    const extension = new CyberCapabilityExtension(registry, {
      sessionLookup: () => 'inv-1',
    });

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
      prompt: 'Investigate DNS activity',
      existingMessages: [],
      isColdStart: true,
    });

    expect(result.promptPrefix).toContain('prefer the cyber capability tools');
    expect(result.customTools?.map((tool) => tool.name)).toEqual([
      'cyber_capability_discover',
      'cyber_capability_execute',
    ]);

    const discoverTool = result.customTools?.find((tool) => tool.name === 'cyber_capability_discover');
    const discoverResult = await discoverTool?.execute('call-1', {
      question: 'What capability can search DNS queries and suspicious domain lookups?',
    });
    const discoverText = textFrom(discoverResult as never);
    expect(discoverText).toContain('search_dns');
  });

  it('executes a capability for investigation-linked sessions', async () => {
    const root = path.join(process.cwd(), 'tmp-cyber-capability-extension');
    rmSync(root, { recursive: true, force: true });
    mkdirSync(root, { recursive: true });
    const filePath = path.join(root, 'artifact.txt');
    writeFileSync(filePath, 'artifact body', 'utf8');

    const registry = new CyberCapabilityRegistry();
    const extension = new CyberCapabilityExtension(registry, {
      sessionLookup: () => 'inv-1',
      permissionResolver: () => 'allow',
    });
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
      prompt: 'Inspect an artifact',
      existingMessages: [],
      isColdStart: true,
    });

    const executeTool = result.customTools?.find((tool) => tool.name === 'cyber_capability_execute');
    const execution = await executeTool?.execute(
      'call-2',
      { name: 'inspect_file', input: { filePath } },
      undefined as never,
      undefined as never,
      { sessionId: 'session-1', cwd: root }
    );
    const executionText = textFrom(execution as never);
    expect(executionText).toContain('artifact.txt');
    expect(executionText).toContain('artifact body');

    rmSync(root, { recursive: true, force: true });
  });

  it('denies execution for sessions not linked to an investigation', async () => {
    const registry = new CyberCapabilityRegistry();
    const extension = new CyberCapabilityExtension(registry, {
      sessionLookup: () => null,
    });
    const result = await extension.beforeSessionRun({
      session: {
        id: 'session-2',
        title: 'Standalone',
        status: 'idle',
        mountedPaths: [],
        allowedTools: [],
        memoryEnabled: false,
        createdAt: 1,
        updatedAt: 1,
      },
      prompt: 'Standalone use',
      existingMessages: [],
      isColdStart: true,
    });

    const executeTool = result.customTools?.find((tool) => tool.name === 'cyber_capability_execute');
    const execution = await executeTool?.execute(
      'call-3',
      { name: 'lookup_indicator', input: { indicator: 'evil.example' } },
      undefined as never,
      undefined as never,
      { sessionId: 'session-2' }
    );
    expect(textFrom(execution as never)).toContain('not linked to an investigation');
  });

  it('applies permission guardrails before execution', async () => {
    const registry = new CyberCapabilityRegistry();
    const permissionResolver = vi.fn(() => 'deny' as const);
    const extension = new CyberCapabilityExtension(registry, {
      sessionLookup: () => 'inv-1',
      permissionResolver,
    });
    const result = await extension.beforeSessionRun({
      session: {
        id: 'session-3',
        title: 'Worker',
        status: 'idle',
        mountedPaths: [],
        allowedTools: [],
        memoryEnabled: false,
        createdAt: 1,
        updatedAt: 1,
      },
      prompt: 'Execute safely',
      existingMessages: [],
      isColdStart: true,
    });

    const executeTool = result.customTools?.find((tool) => tool.name === 'cyber_capability_execute');
    const execution = await executeTool?.execute(
      'call-4',
      { name: 'lookup_indicator', input: { indicator: 'evil.example' } },
      undefined as never,
      undefined as never,
      { sessionId: 'session-3' }
    );
    expect(permissionResolver).toHaveBeenCalled();
    expect(textFrom(execution as never)).toContain('permission denied');
  });

  it('blocks high-risk capabilities even if they are registered', async () => {
    const highRiskRegistry = new CyberCapabilityRegistry([
      {
        name: 'lookup_indicator',
        description: 'High-risk mock capability',
        inputSchema: { type: 'object', properties: { indicator: { type: 'string' } } },
        outputSchema: { type: 'object', properties: { ok: { type: 'boolean' } } },
        riskLevel: 'HIGH',
        permissionsRequired: ['network:external'],
        timeoutMs: 1000,
        cost: 'LOW',
        supportedAdapters: ['mock'],
        tags: ['indicator'],
        canAnswer: ['lookup indicator'],
        actionCategory: 'HIGH_RISK_ACTION',
        executor: async () => ({ ok: true }),
      } satisfies CyberCapabilityDefinition,
    ]);

    const extension = new CyberCapabilityExtension(highRiskRegistry, {
      sessionLookup: () => 'inv-1',
      allowedRiskLevels: ['LOW', 'MEDIUM'],
      permissionResolver: () => 'allow',
    });
    const result = await extension.beforeSessionRun({
      session: {
        id: 'session-4',
        title: 'Worker',
        status: 'idle',
        mountedPaths: [],
        allowedTools: [],
        memoryEnabled: false,
        createdAt: 1,
        updatedAt: 1,
      },
      prompt: 'Execute guarded capability',
      existingMessages: [],
      isColdStart: true,
    });

    const discoverTool = result.customTools?.find((tool) => tool.name === 'cyber_capability_discover');
    const discover = await discoverTool?.execute('call-5', { question: 'lookup indicator' });
    expect(textFrom(discover as never)).not.toContain('High-risk mock capability');

    const executeTool = result.customTools?.find((tool) => tool.name === 'cyber_capability_execute');
    const execution = await executeTool?.execute(
      'call-6',
      { name: 'lookup_indicator', input: { indicator: 'evil.example' } },
      undefined as never,
      undefined as never,
      { sessionId: 'session-4' }
    );
    expect(textFrom(execution as never)).toContain('disallowed risk level HIGH');
  });

  it('requires explicit human approval and writes an audit record for high-risk cyber actions', async () => {
    const auditTrail = new CyberActionAuditTrail();
    const registry = new CyberCapabilityRegistry([
      {
        name: 'lookup_indicator',
        description: 'High-risk mock capability',
        inputSchema: { type: 'object', properties: { indicator: { type: 'string' } } },
        outputSchema: { type: 'object', properties: { ok: { type: 'boolean' } } },
        riskLevel: 'HIGH',
        permissionsRequired: ['network:external'],
        timeoutMs: 1000,
        cost: 'LOW',
        supportedAdapters: ['mock'],
        tags: ['disable account'],
        canAnswer: ['disable suspicious account'],
        actionCategory: 'HIGH_RISK_ACTION',
        executor: async () => ({ ok: true }),
      } satisfies CyberCapabilityDefinition,
    ]);

    const extension = new CyberCapabilityExtension(registry, {
      sessionLookup: () => 'inv-9',
      permissionResolver: () => 'allow',
      allowedRiskLevels: ['LOW', 'MEDIUM', 'HIGH'],
      permissionPolicy: new CyberPermissionPolicy(),
      auditTrail,
      resolveExecutionContext: () => ({ explicitHumanApproval: false }),
    });

    const result = await extension.beforeSessionRun({
      session: {
        id: 'session-9',
        title: 'Worker',
        status: 'idle',
        mountedPaths: [],
        allowedTools: [],
        memoryEnabled: false,
        createdAt: 1,
        updatedAt: 1,
      },
      prompt: 'Disable suspicious account',
      existingMessages: [],
      isColdStart: true,
    });

    const executeTool = result.customTools?.find((tool) => tool.name === 'cyber_capability_execute');
    const denied = await executeTool?.execute(
      'call-7',
      { name: 'lookup_indicator', input: { indicator: 'svc-account' } },
      undefined as never,
      undefined as never,
      { sessionId: 'session-9' }
    );
    expect(textFrom(denied as never)).toContain('requires explicit human approval');
    expect(auditTrail.list()[0]?.approvalState).toBe('REQUIRES_EXPLICIT_HUMAN_APPROVAL');
    expect(auditTrail.list()[0]?.result.status).toBe('denied');
  });

  it('mirrors cyber audit records into investigation activity', async () => {
    const { db } = makeDb();
    const investigationService = new InvestigationService(db);
    const created = investigationService.create({ title: 'Case', objective: 'Investigate suspicious file activity' });
    investigationService.linkSession(created.id, 'session-audit', 'worker');

    const auditTrail = new CyberActionAuditTrail();
    const registry = new CyberCapabilityRegistry();
    const extension = new CyberCapabilityExtension(registry, {
      sessionLookup: (sessionId) => investigationService.getInvestigationIdBySessionId(sessionId),
      permissionResolver: () => 'allow',
      auditTrail,
      onAuditRecord: (record) => {
        if (!record.investigationId) return;
        investigationService.recordEvent(
          record.investigationId,
          'CYBER_ACTION_AUDITED',
          record.actor,
          `Cyber action ${record.result.status}: ${record.capabilityName}`,
          {
            capabilityName: record.capabilityName,
            actionCategory: record.actionCategory,
            approvalState: record.approvalState,
            result: record.result,
            target: record.target,
          }
        );
      },
    });

    const root = path.join(process.cwd(), 'tmp-cyber-capability-audit-investigation');
    rmSync(root, { recursive: true, force: true });
    mkdirSync(root, { recursive: true });
    const filePath = path.join(root, 'artifact.txt');
    writeFileSync(filePath, 'artifact body', 'utf8');

    const result = await extension.beforeSessionRun({
      session: {
        id: 'session-audit',
        title: 'Worker',
        status: 'idle',
        mountedPaths: [],
        allowedTools: [],
        memoryEnabled: false,
        createdAt: 1,
        updatedAt: 1,
      },
      prompt: 'Inspect an artifact',
      existingMessages: [],
      isColdStart: true,
    });

    const executeTool = result.customTools?.find((tool) => tool.name === 'cyber_capability_execute');
    await executeTool?.execute(
      'call-8',
      { name: 'inspect_file', input: { filePath } },
      undefined as never,
      undefined as never,
      { sessionId: 'session-audit', cwd: root }
    );

    const updated = investigationService.get(created.id)!;
    expect(updated.activity.map((item) => item.type)).toContain('CYBER_ACTION_AUDITED');
    const auditEvent = updated.activity.find((item) => item.type === 'CYBER_ACTION_AUDITED');
    expect(auditEvent?.data).toMatchObject({
      capabilityName: 'inspect_file',
      actionCategory: 'READ_ONLY',
    });

    rmSync(root, { recursive: true, force: true });
  });

  it('audits failed executions (incl. timeouts) before surfacing the error', async () => {
    const { db } = makeDb();
    const investigationService = new InvestigationService(db);
    const created = investigationService.create({ title: 'Case', objective: 'Timeout behavior' });
    investigationService.linkSession(created.id, 'session-fail', 'worker');

    const auditTrail = new CyberActionAuditTrail();
    const registry = new CyberCapabilityRegistry([
      {
        name: 'search_dns',
        description: 'Hanging capability.',
        inputSchema: { type: 'object', properties: {} },
        outputSchema: { type: 'object', properties: {} },
        riskLevel: 'LOW',
        permissionsRequired: [],
        timeoutMs: 30,
        cost: 'LOW',
        supportedAdapters: [],
        tags: ['dns'],
        canAnswer: ['search dns'],
        executor: async () => {
          await new Promise((resolve) => setTimeout(resolve, 5000));
          return { records: [] };
        },
      },
    ]);
    const extension = new CyberCapabilityExtension(registry, {
      sessionLookup: (sessionId) => investigationService.getInvestigationIdBySessionId(sessionId),
      permissionResolver: () => 'allow',
      auditTrail,
      onAuditRecord: (record) => {
        if (!record.investigationId) return;
        investigationService.recordEvent(
          record.investigationId,
          'CYBER_ACTION_AUDITED',
          record.actor,
          `Cyber action ${record.result.status}: ${record.capabilityName}`,
          { capabilityName: record.capabilityName, result: record.result }
        );
      },
    });

    const result = await extension.beforeSessionRun({
      session: {
        id: 'session-fail',
        title: 'Worker',
        status: 'idle',
        mountedPaths: [],
        allowedTools: [],
        memoryEnabled: false,
        createdAt: 1,
        updatedAt: 1,
      },
      prompt: 'Trigger a timeout',
      existingMessages: [],
      isColdStart: true,
    });
    const executeTool = result.customTools?.find((tool) => tool.name === 'cyber_capability_execute');

    await expect(
      executeTool?.execute(
        'call-9',
        { name: 'search_dns', input: {} },
        undefined as never,
        undefined as never,
        { sessionId: 'session-fail' }
      )
    ).rejects.toThrow(/timed out/);

    // The failure is durably mirrored into the investigation timeline.
    const updated = investigationService.get(created.id)!;
    const failureEvent = updated.activity.find((item) => item.type === 'CYBER_ACTION_AUDITED');
    expect(failureEvent).toBeDefined();
    expect((failureEvent?.data as { result?: { status?: string } }).result?.status).toBe('failed');

    // And recorded in the in-memory trail.
    const failedRecords = auditTrail.list().filter((r) => r.result.status === 'failed');
    expect(failedRecords).toHaveLength(1);
    expect(failedRecords[0].capabilityName).toBe('search_dns');
  });
});
