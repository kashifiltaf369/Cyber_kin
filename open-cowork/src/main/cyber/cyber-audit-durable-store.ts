/**
 * @module main/cyber/cyber-audit-durable-store
 *
 * Durable, append-only, hash-chained audit log for cyber capability actions.
 *
 * Complements the in-memory `CyberActionAuditTrail`: every record appended to
 * the trail is also serialized as one JSON line with integrity metadata:
 *
 *   {"seq":N,"prevHash":"…","hash":"…","record":{…}}
 *
 * where `hash = sha256(prevHash + canonicalJson(record))`. The chain makes
 * silent tampering detectable: editing or deleting any line breaks every
 * hash from that point on, and `verifyCyberAuditFile` pinpoints the first
 * broken sequence number.
 *
 * Notes on guarantees (truthful scope):
 *  - Tamper-EVIDENT, not tamper-PROOF: a determined attacker with write
 *    access to the file can rewrite the whole chain (no MAC / external
 *    anchor). Detection covers partial edits, truncation-after-the-fact
 *    reconstruction gaps, and casual modification.
 *  - Appends use a single `appendFileSync` per record; concurrent appends
 *    from one process are serialized by the caller (the trail's synchronous
 *    `append`).
 */

import { createHash } from 'node:crypto';
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
} from 'node:fs';
import path from 'node:path';

import type { CyberActionAuditRecord } from './cyber-permission-policy';

export interface ChainedAuditLine {
  seq: number;
  prevHash: string;
  hash: string;
  record: CyberActionAuditRecord;
}

const GENESIS_HASH = '0'.repeat(64);

/** Deterministic JSON serialization for hashing (sorted object keys). */
export function canonicalAuditJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalAuditJson(item)).join(',')}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${JSON.stringify(k)}:${canonicalAuditJson(v)}`);
  return `{${entries.join(',')}}`;
}

function computeRecordHash(prevHash: string, record: CyberActionAuditRecord): string {
  return createHash('sha256').update(prevHash + canonicalAuditJson(record)).digest('hex');
}

/**
 * Append-only hash-chained audit file. One instance per file; safe to attach
 * to a `CyberActionAuditTrail` via its `onAppend` hook.
 */
export class CyberAuditDurableStore {
  private readonly filePath: string;
  private lastSeq = 0;
  private lastHash = GENESIS_HASH;

  constructor(filePath: string) {
    this.filePath = filePath;
    if (existsSync(filePath)) {
      // Continue the existing chain from its last intact line.
      const tail = readLastAuditLine(filePath);
      if (tail) {
        this.lastSeq = tail.seq;
        this.lastHash = tail.hash;
      }
    } else {
      const dir = path.dirname(filePath);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
    }
  }

  get path(): string {
    return this.filePath;
  }

  /** Chain position of the most recently appended record. */
  get tail(): { seq: number; hash: string } {
    return { seq: this.lastSeq, hash: this.lastHash };
  }

  /**
   * Append one record to the chain and durably write it. Throws if the write
   * fails — callers must not continue executing cyber actions with a silent
   * audit gap.
   */
  append(record: CyberActionAuditRecord): ChainedAuditLine {
    const seq = this.lastSeq + 1;
    const prevHash = this.lastHash;
    const hash = computeRecordHash(prevHash, record);
    const line: ChainedAuditLine = { seq, prevHash, hash, record };
    appendFileSync(this.filePath, `${JSON.stringify(line)}\n`, 'utf8');
    this.lastSeq = seq;
    this.lastHash = hash;
    return line;
  }
}

function readLastAuditLine(filePath: string): ChainedAuditLine | null {
  const size = statSync(filePath).size;
  if (size === 0) return null;
  const handle = readFileSync(filePath);
  // Read only the tail (last 64 KiB is far more than enough for one line).
  const window = handle.subarray(Math.max(0, size - 64 * 1024)).toString('utf8');
  const lines = window.split('\n').filter((line) => line.trim().length > 0);
  const last = lines.at(-1);
  if (!last) return null;
  try {
    return JSON.parse(last) as ChainedAuditLine;
  } catch {
    return null;
  }
}

export interface CyberAuditVerificationResult {
  ok: boolean;
  records: number;
  /** Sequence number of the first broken/invalid line, when !ok. */
  brokenAtSeq?: number;
  reason?: 'bad_json' | 'hash_mismatch' | 'prev_hash_mismatch' | 'seq_gap' | 'empty';
}

/**
 * Verify the full hash chain of an audit file. Recomputes every record hash
 * and checks linkage (seq continuity + prevHash). Returns the first break.
 */
export function verifyCyberAuditFile(filePath: string): CyberAuditVerificationResult {
  if (!existsSync(filePath)) {
    return { ok: false, records: 0, reason: 'empty' };
  }
  const content = readFileSync(filePath, 'utf8');
  const lines = content.split('\n').filter((line) => line.trim().length > 0);
  if (lines.length === 0) {
    return { ok: false, records: 0, reason: 'empty' };
  }

  let prevHash = GENESIS_HASH;
  let expectedSeq = 1;
  for (const line of lines) {
    let parsed: ChainedAuditLine;
    try {
      parsed = JSON.parse(line) as ChainedAuditLine;
    } catch {
      return { ok: false, records: expectedSeq - 1, brokenAtSeq: expectedSeq, reason: 'bad_json' };
    }
    if (parsed.seq !== expectedSeq) {
      return { ok: false, records: expectedSeq - 1, brokenAtSeq: expectedSeq, reason: 'seq_gap' };
    }
    if (parsed.prevHash !== prevHash) {
      return { ok: false, records: expectedSeq - 1, brokenAtSeq: expectedSeq, reason: 'prev_hash_mismatch' };
    }
    const expectedHash = computeRecordHash(prevHash, parsed.record);
    if (parsed.hash !== expectedHash) {
      return { ok: false, records: expectedSeq - 1, brokenAtSeq: expectedSeq, reason: 'hash_mismatch' };
    }
    prevHash = parsed.hash;
    expectedSeq += 1;
  }
  return { ok: true, records: lines.length };
}
