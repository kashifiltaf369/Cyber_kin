/**
 * Security tests: durable hash-chained cyber audit store.
 *
 * Maps to SECURITY_THREAT_MODEL.md THREAT-16 (Audit log tampering).
 * The in-memory trail is deep-frozen and deep-cloned (see
 * security-audit-trail.test.ts); this module adds the durable layer:
 * append-only JSONL with a per-record SHA-256 chain (seq + prevHash + hash)
 * so partial tampering is detectable and attributable to a sequence number.
 */

import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  CyberAuditDurableStore,
  canonicalAuditJson,
  verifyCyberAuditFile,
} from '../src/main/cyber/cyber-audit-durable-store';
import type { CyberActionAuditRecord } from '../src/main/cyber/cyber-permission-policy';

function makeRecord(overrides: Partial<CyberActionAuditRecord> = {}): CyberActionAuditRecord {
  return {
    id: overrides.id ?? `rec-${Math.random().toString(36).slice(2, 10)}`,
    actor: 'agent',
    agent: 'session-1',
    timestamp: 1_700_000_000_000,
    investigationId: 'inv-1',
    capabilityName: 'inspect_file',
    actionCategory: 'READ_ONLY',
    target: 'artifact.bin',
    parameters: { filePath: 'artifact.bin' },
    result: { status: 'executed', summary: 'Executed capability inspect_file' },
    approvalState: 'NOT_REQUIRED',
    ...overrides,
  };
}

function tempFile(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cyber-audit-store-'));
  return path.join(dir, 'cyber-audit.jsonl');
}

describe('canonicalAuditJson', () => {
  it('is deterministic regardless of key insertion order', () => {
    const a = canonicalAuditJson({ b: 1, a: { d: 2, c: 3 } });
    const b = canonicalAuditJson({ a: { c: 3, d: 2 }, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":{"c":3,"d":2},"b":1}');
  });
});

describe('CyberAuditDurableStore', () => {
  it('appends records with a continuous verified chain', () => {
    const file = tempFile();
    const store = new CyberAuditDurableStore(file);

    store.append(makeRecord({ id: 'r1' }));
    store.append(makeRecord({ id: 'r2' }));
    store.append(makeRecord({ id: 'r3' }));

    expect(store.tail.seq).toBe(3);
    const verification = verifyCyberAuditFile(file);
    expect(verification.ok).toBe(true);
    expect(verification.records).toBe(3);
  });

  it('detects record tampering and names the broken sequence', () => {
    const file = tempFile();
    const store = new CyberAuditDurableStore(file);
    store.append(makeRecord({ id: 'r1' }));
    store.append(makeRecord({ id: 'r2' }));

    // Tamper with the first record's summary in place.
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    const first = JSON.parse(lines[0]);
    first.record.result.summary = 'TAMPERED SUMMARY';
    lines[0] = JSON.stringify(first);
    fs.writeFileSync(file, lines.join('\n'), 'utf8');

    const verification = verifyCyberAuditFile(file);
    expect(verification.ok).toBe(false);
    expect(verification.brokenAtSeq).toBe(1);
    expect(verification.reason).toBe('hash_mismatch');
  });

  it('detects deleted lines as a sequence gap', () => {
    const file = tempFile();
    const store = new CyberAuditDurableStore(file);
    store.append(makeRecord({ id: 'r1' }));
    store.append(makeRecord({ id: 'r2' }));
    store.append(makeRecord({ id: 'r3' }));

    // Delete the middle record.
    const lines = fs.readFileSync(file, 'utf8').split('\n').filter((l) => l.trim());
    fs.writeFileSync(file, [lines[0], lines[2], ''].join('\n'), 'utf8');

    const verification = verifyCyberAuditFile(file);
    expect(verification.ok).toBe(false);
    expect(verification.brokenAtSeq).toBe(2);
    expect(verification.reason).toBe('seq_gap');
  });

  it('continues an existing chain after a restart', () => {
    const file = tempFile();
    const first = new CyberAuditDurableStore(file);
    first.append(makeRecord({ id: 'r1' }));
    const tailAfterFirst = first.tail;
    expect(tailAfterFirst.seq).toBe(1);

    // New process, same file: the chain continues, not restarts.
    const second = new CyberAuditDurableStore(file);
    expect(second.tail.seq).toBe(1);
    expect(second.tail.hash).toBe(tailAfterFirst.hash);
    second.append(makeRecord({ id: 'r2' }));

    const verification = verifyCyberAuditFile(file);
    expect(verification.ok).toBe(true);
    expect(verification.records).toBe(2);
  });

  it('wires through CyberActionAuditTrail.setDurableSink', async () => {
    const { CyberActionAuditTrail } = await import('../src/main/cyber/cyber-permission-policy');
    const file = tempFile();
    const store = new CyberAuditDurableStore(file);
    const trail = new CyberActionAuditTrail();
    trail.setDurableSink((record) => store.append(record));

    trail.append(makeRecord({ id: 'wired-1' }));
    trail.append(makeRecord({ id: 'wired-2' }));

    const verification = verifyCyberAuditFile(file);
    expect(verification.ok).toBe(true);
    expect(verification.records).toBe(2);

    // The in-memory trail still exposes the same records.
    expect(trail.list().map((r) => r.id)).toEqual(['wired-1', 'wired-2']);
  });
});
