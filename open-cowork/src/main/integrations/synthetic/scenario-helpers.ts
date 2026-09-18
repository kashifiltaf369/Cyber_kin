/**
 * @module main/integrations/synthetic/scenario-helpers
 *
 * Deterministic helpers shared by scenario fixtures so timestamps, hostnames
 * and indicators stay stable across runs.
 */

import type { SyntheticScenario } from './scenario-types';

/** Epoch reference: 2025-09-15 14:00:00 UTC. All scenarios anchor here. */
export const SCENARIO_EPOCH_MS = Date.UTC(2025, 8, 15, 14, 0, 0);

/** Returns a deterministic offset in ms from SCENARIO_EPOCH_MS. */
export function ts(offsetMinutes: number): number {
  return SCENARIO_EPOCH_MS + offsetMinutes * 60_000;
}

export const SCENARIO_HOSTS = {
  WS01: { hostname: 'CYBER-WIN-WS01', ip: '10.10.20.31', os: 'Windows 11 23H2', role: 'workstation' },
  WS02: { hostname: 'CYBER-WIN-WS02', ip: '10.10.20.32', os: 'Windows 11 23H2', role: 'workstation' },
  WS03: { hostname: 'CYBER-WIN-WS03', ip: '10.10.20.33', os: 'Windows 11 23H2', role: 'workstation' },
  FS01: { hostname: 'CYBER-WIN-FS01', ip: '10.10.10.11', os: 'Windows Server 2022', role: 'file-server' },
  DC01: { hostname: 'CYBER-WIN-DC01', ip: '10.10.10.5', os: 'Windows Server 2022', role: 'domain-controller' },
  EXCH: { hostname: 'CYBER-EXCH-01', ip: '10.10.10.20', os: 'Windows Server 2019', role: 'exchange' },
} as const;

export const SCENARIO_USERS = {
  alice: { username: 'a.harper', displayName: 'Alice Harper', department: 'finance', privileged: false },
  bob: { username: 'b.lin', displayName: 'Bob Lin', department: 'finance', privileged: false },
  carol: { username: 'c.singh', displayName: 'Carol Singh', department: 'it-ops', privileged: false },
  dave: { username: 'd.romero', displayName: 'Dave Romero', department: 'it-ops', privileged: true },
  svc: { username: 'svc-backup', displayName: 'Backup Service Account', department: 'it-ops', privileged: true },
} as const;

/**
 * Lightweight deterministic PRNG (Mulberry32) so scenario outputs are stable
 * for snapshot tests but still varied.
 */
export function createDeterministicRng(seed: number): () => number {
  let state = seed >>> 0;
  return function next(): number {
    state = (state + 0x6D2B79F5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Stable id generator: scenario prefix + counter. */
export function makeIdFactory(prefix: string): () => string {
  let counter = 0;
  return () => `${prefix}-${(++counter).toString().padStart(4, '0')}`;
}

export function listScenarios(scenarios: SyntheticScenario[]): SyntheticScenario[] {
  return [...scenarios];
}