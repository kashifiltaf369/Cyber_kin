/**
 * Security tests: CyberActionAuditTrail immutability and tamper resistance.
 *
 * Maps to SECURITY_THREAT_MODEL.md THREAT-16 (Audit log tampering) — CRITICAL severity.
 *
 * Scope: Verify current behavior of CyberActionAuditTrail:
 *   - Deep Object.freeze at append time (nested objects immutable)
 *   - list()/getByInvestigationId() return deep clones (caller mutations
 *     cannot reach trail state)
 *   - In-memory records expose no chain data themselves; the durable layer
 *     (CyberAuditDurableStore, see security-audit-durable.test.ts) appends
 *     every record to a hash-chained cyber-audit.jsonl beside the app
 *     database. Remaining limitation: the durable chain is tamper-evident,
 *     not tamper-proof (no MAC / external anchor).
 *
 * Historic "DOCUMENTS GAP" entries have been updated to CLOSED GAP regression
 * guards after the implementation hardened. The in-memory no-chain gap below
 * is still accurate for the trail's own API surface.
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

    it('CLOSED GAP: nested "parameters" object IS deeply frozen (mutation rejected)', () => {
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

      expect(threw).toBe(true);
      expect(JSON.stringify(record.parameters)).toBe(before);
      expect(Object.isFrozen((record as unknown as { parameters: Record<string, unknown> }).parameters)).toBe(true);
    });

    it('CLOSED GAP: "result.details" nested object IS deeply frozen', () => {
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

      expect(threw).toBe(true);
      expect((record.result.details as Record<string, unknown>).sha256).toBe('deadbeefcafebabe');
    });

    it('CLOSED GAP: arbitrary nested objects in audit input parameters are frozen (immutable after audit)', () => {
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

      expect(threw).toBe(true);
      expect(nested.inner.secret).toBe('SHOULD-NOT-BE-MUTABLE-IF-DEEP-FREEZE');
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

    it('CLOSED GAP: list() returns deep clones — mutating nested details through list() does NOT affect trail state', () => {
      const trail = new CyberActionAuditTrail();
      makeAuditRecord(trail);

      const listCopy = trail.list();
      const details = listCopy[0].result.details as Record<string, unknown>;
      details.sha256 = 'ALTERED-VIA-LIST-COPY';

      const freshList = trail.list();
      expect((freshList[0].result.details as Record<string, unknown>).sha256).toBe('deadbeefcafebabe');
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
