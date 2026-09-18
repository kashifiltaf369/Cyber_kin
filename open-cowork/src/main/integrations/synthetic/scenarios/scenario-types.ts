export type ScenarioId =
  | 'suspicious-powershell'
  | 'credential-theft'
  | 'lateral-movement'
  | 'suspicious-login'
  | 'malicious-document'
  | 'data-exfiltration'
  | 'false-positive';

export interface SyntheticScenario {
  id: ScenarioId;
  description: string;
  run(): Promise<void>;
}
