/**
 * Security tests: CyberActionAuditTrail immutability and tamper resistance.
 *
 * Maps to SECURITY_THREAT_MODEL.md THREAT-16 (Audit log tampering) — CRITICAL severity.
 *
 * Scope: Verify current behavior of CyberActionAuditTrail including documented gaps:
 *   - Shallow Object.freeze (nested objects remain mutable)
 *   - In-memory array without append-only structural guarantees
 *   - No hash chain or MAC for integrity verification
 *
 * These tests DOCUMENT actual behavior; they do NOT patch or weaken controls.
 */

import { describe, it, expect } from 'vitest';
import {
  CyberActionAuditTrail,
  CyberPermissionPolicy,
  classifyCapabilityRisk,
} from '../src/main/cyber/cyber-permission-policy';

function makeCapability(overrides: Partial<{
  name: string;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  tags: string[];
  permissionsRequired: string[];
}> = {}) {
  return {
    name: overrides.name ?? 'inspect_file',
    riskLevel: overrides.riskLevel ?? 'LOW',
    tags: overrides.tags ?? ['file', 'read'],
    permissionsRequired: overrides.permissionsRequired ?? ['filesystem:read'],
  } as const;
}

function makeAuditRecord(trail: CyberActionAuditTrail) {
  const policy = new CyberPermissionPolicy();
  const capability = makeCapability();
  const decision = policy.decide(
    capability,
    {
      filePath: 'artifact.bin',
      parameters: { hash: 'abc123', reason: 'initial triage' },
    },
    false
  );
  return policy.audit(
    trail,
    capability,
    {
      filePath: 'artifact.bin',
      nested: {
        inner: {
          secret: 'SHOULD-NOT-BE-MUTABLE-IF-DEEP-FREEZE',
        },
      },
    },
    {
      sessionId: 'sess-audit-1',
      investigationId: 'inv-audit-1',
      actor: 'agent',
      agent: 'Endpoint Investigator',
    },
    decision,
    {
      status: 'executed',
      summary: 'Inspected artifact.bin',
      details: {
        sha256: 'deadbeefcafebabe',
        fileSize: 4096,
        deeply: {
          nested: {
            value: 'mutable-if-shallow-freeze-only',
          },
        },
      },
    }
  );
}

describe('THREAT-16: CyberActionAuditTrail tamper resistance', () => {
  describe('Individual record freeze behavior', () => {
    it('prevents mutation of top-level scalar fields via Object.freeze', () => {
      const trail = new CyberActionAuditTrail();
      const record = makeAuditRecord(trail);

      expect(() => {
        ((record as unknown) as { target: string }).target = 'tampered-target';
      }).toThrow();

      expect(() => {
        ((record as unknown) as { capabilityName: string }).capabilityName = 'changed-cap';
      }).toThrow();

      expect(() => {
        ((record as unknown) as { approvalState: string }).approvalState = 'APPROVED';
      }).toThrow();

      expect(record.target).toBe('artifact.bin');
      expect(record.approvalState).toBe('NOT_REQUIRED');
    });

    it('DOCUMENTS GAP: nested "parameters" object is NOT deeply frozen (shallow freeze only)', () => {
      const trail = new CyberActionAuditTrail();
      const record = makeAuditRecord(trail);

      const before = JSON.stringify(record.parameters);
      let threw = false;
      try {
        ((record as unknown) as { parameters: Record<string, unknown> }).parameters.hash = 'TAMPERED-HASH';
        ((record as unknown) as { parameters: Record<string, unknown> }).parameters.newField = 'INJECTED';
      } catch (_e) {
        threw = true;
      }

      expect(threw).toBe(false);
      expect(JSON.stringify(record.parameters)).not.toBe(before);
      expect(((record as unknown) as { parameters: Record<string, unknown> }).parameters.newField).toBe('INJECTED');
    });

    it('DOCUMENTS GAP: "result.details" nested object is NOT deeply frozen', () => {
      const trail = new CyberActionAuditTrail();
      const record = makeAuditRecord(trail);

      const originalSha = (record.result.details as Record<string, unknown>)?.sha256;
      expect(originalSha).toBe('deadbeefcafebabe');

      let threw = false;
      try {
        const details = record.result.details as Record<string, unknown>;
        details.sha256 = 'TAMPERED-SHA';
        details.fakeEvidence = 'planted';
        ((details.deeply as Record<string, unknown>).nested as Record<string, unknown>).value = 'corrupted';
      } catch (_e) {
        threw = true;
      }

      expect(threw).toBe(false);
      expect((record.result.details as Record<string, unknown>).sha256).toBe('TAMPERED-SHA');
      expect((record.result.details as Record<string, unknown>).fakeEvidence).toBe('planted');
    });

    it('DOCUMENTS GAP: arbitrary nested objects in audit input parameters survive shallow freeze and remain mutable', () => {
      const trail = new CyberActionAuditTrail();
      const record = makeAuditRecord(trail);

      const params = record.parameters as Record<string, unknown>;
      const nested = params.nested as Record<string, Record<string, string>>;

      let threw = false;
      try {
        nested.inner.secret = 'OVERWRITTEN-AFTER-AUDIT';
      } catch (_e) {
        threw = true;
      }

      expect(threw).toBe(false);
      expect(nested.inner.secret).toBe('OVERWRITTEN-AFTER-AUDIT');
    });
  });

  describe('Records list behavior', () => {
    it('list() returns a shallow copy (caller array mutations do not affect trail)', () => {
      const trail = new CyberActionAuditTrail();
      makeAuditRecord(trail);
      makeAuditRecord(trail);

      const listA = trail.list();
      const listB = trail.list();
      expect(listA).toHaveLength(2);
      expect(listB).toHaveLength(2);

      listA.pop();
      expect(listA).toHaveLength(1);
      expect(trail.list()).toHaveLength(2);
      expect(listB).toHaveLength(2);
    });

    it('DOCUMENTS GAP: shallow-copy array shares the same record object references; mutating nested details through list() affects trail state', () => {
      const trail = new CyberActionAuditTrail();
      makeAuditRecord(trail);

      const listCopy = trail.list();
      const details = listCopy[0].result.details as Record<string, unknown>;
      details.sha256 = 'ALTERED-VIA-LIST-COPY';

      const freshList = trail.list();
      expect((freshList[0].result.details as Record<string, unknown>).sha256).toBe('ALTERED-VIA-LIST-COPY');
    });
  });

  describe('Per-investigation scoping', () => {
    it('filters records by investigationId without leaking cross-investigation references', () => {
      const trail = new CyberActionAuditTrail();
      const policy = new CyberPermissionPolicy();

      const cap = makeCapability();
      const dec = policy.decide(cap, { filePath: 'a' }, false);

      policy.audit(trail, cap, { filePath: 'a' }, { sessionId: 's1', investigationId: 'inv-A' }, dec, {
        status: 'executed',
        summary: 'A-only',
      });
      policy.audit(trail, cap, { filePath: 'b' }, { sessionId: 's1', investigationId: 'inv-B' }, dec, {
        status: 'executed',
        summary: 'B-only',
      });
      policy.audit(trail, cap, { filePath: 'c' }, { sessionId: 's1', investigationId: null }, dec, {
        status: 'executed',
        summary: 'null-inv',
      });

      expect(trail.getByInvestigationId('inv-A').map((r) => r.target)).toEqual(['a']);
      expect(trail.getByInvestigationId('inv-B').map((r) => r.target)).toEqual(['b']);
      expect(trail.list()).toHaveLength(3);
    });
  });

  describe('Integrity verification (absence)', () => {
    it('DOCUMENTS GAP: no integrity hash chain or MAC is exposed — identical records produce no verifiable chain', () => {
      const trail = new CyberActionAuditTrail();
      const policy = new CyberPermissionPolicy();
      const cap = makeCapability();
      const dec = policy.decide(cap, { filePath: 'x' }, false);

      const r1 = policy.audit(trail, cap, { filePath: 'x' }, { sessionId: 's', investigationId: 'i' }, dec, {
        status: 'executed',
        summary: 'first',
      });
      const r2 = policy.audit(trail, cap, { filePath: 'x' }, { sessionId: 's', investigationId: 'i' }, dec, {
        status: 'executed',
        summary: 'second',
      });

      const recordShape = Object.keys(r2);
      expect(recordShape).not.toContain('previousHash');
      expect(recordShape).not.toContain('mac');
      expect(recordShape).not.toContain('signature');
      expect(r1.id).toBeDefined();
      expect(r2.id).toBeDefined();
      expect(r1.id).not.toBe(r2.id);
    });
  });

  describe('classifyCapabilityRisk baseline sanity (used by audit)', () => {
    it('still classifies the base cases correctly alongside THREAT-05 classifier tests', () => {
      expect(classifyCapabilityRisk(makeCapability({ name: 'delete_artifact', tags: ['delete'] }))).toBe(
        'DESTRUCTIVE_ACTION'
      );
      expect(
        classifyCapabilityRisk(makeCapability({ name: 'isolate_host', tags: ['firewall'], riskLevel: 'HIGH' }))
      ).toBe('HIGH_RISK_ACTION');
      expect(classifyCapabilityRisk(makeCapability({ name: 'query_logs', tags: ['search'] }))).toBe('READ_ONLY');
      expect(classifyCapabilityRisk(makeCapability({ name: 'hash_file', tags: ['hash'], riskLevel: 'MEDIUM' }))).toBe(
        'ANALYSIS'
      );
    });
  });
});
