/**
 * @module main/integrations/synthetic/scenarios
 *
 * Registry of all bundled synthetic scenarios. Use listSyntheticScenarios()
 * to enumerate, or buildSyntheticScenario(id) to instantiate.
 */

import type { ScenarioId, SyntheticScenario } from '../scenario-types';
import { suspiciousPowershellScenario } from './01-suspicious-powershell';
import { credentialTheftScenario } from './02-credential-theft';
import { lateralMovementScenario } from './03-lateral-movement';
import { suspiciousLoginScenario } from './04-suspicious-login';
import { maliciousDocumentScenario } from './05-malicious-document';
import { dataExfiltrationScenario } from './06-data-exfiltration';
import { falsePositiveScenario } from './07-false-positive';

export const SYNTHETIC_SCENARIOS: ReadonlyArray<SyntheticScenario> = [
  suspiciousPowershellScenario,
  credentialTheftScenario,
  lateralMovementScenario,
  suspiciousLoginScenario,
  maliciousDocumentScenario,
  dataExfiltrationScenario,
  falsePositiveScenario,
] as const;

const SCENARIO_BY_ID: Record<ScenarioId, SyntheticScenario> = {
  'suspicious-powershell': suspiciousPowershellScenario,
  'credential-theft': credentialTheftScenario,
  'lateral-movement': lateralMovementScenario,
  'suspicious-login': suspiciousLoginScenario,
  'malicious-document': maliciousDocumentScenario,
  'data-exfiltration': dataExfiltrationScenario,
  'false-positive': falsePositiveScenario,
};

export function listSyntheticScenarios(): SyntheticScenario[] {
  return [...SYNTHETIC_SCENARIOS];
}

export function buildSyntheticScenario(id: ScenarioId): SyntheticScenario {
  const scenario = SCENARIO_BY_ID[id];
  if (!scenario) {
    throw new Error(`Unknown synthetic scenario: ${id}`);
  }
  return scenario;
}