/**
 * @module main/integrations/synthetic/scenario-types
 *
 * Type contracts for the synthetic cybersecurity investigation environment.
 *
 * Per CYBER_BUILD_RULES rule 23 ("Never fabricate cybersecurity evidence"),
 * this environment exists ONLY to exercise the real investigation architecture
 * during development and demos. Every record is explicitly labelled
 * SYNTHETIC so investigators and the system cannot mistake it for real
 * telemetry.
 */

import type {
  DnsRecord,
  EventRecord,
  FileAnalysisReport,
  IdentityActivityRecord,
  IndicatorLookupResult,
  NetworkConnectionRecord,
  ProcessRecord,
} from '../integration-types';

/** Sentinel value attached to every synthetic record to prevent accidental real-world use. */
export const SYNTHETIC_WATERMARK = 'SYNTHETIC_DEMO_DATA';

export type ScenarioId =
  | 'suspicious-powershell'
  | 'credential-theft'
  | 'lateral-movement'
  | 'suspicious-login'
  | 'malicious-document'
  | 'data-exfiltration'
  | 'false-positive';

export interface ScenarioSuspicionLevel {
  /** Free-form suspicion narrative — what an investigator should expect to find. */
  expectedFindings: string[];
  /** Hypotheses that should be SUPPORTED by a competent investigator. */
  expectedHypotheses: string[];
  /** Things that look suspicious at first glance but are actually benign. */
  decoys: string[];
}

export interface ScenarioObjective {
  /** Investigator-facing scenario title, prefixed [SYNTHETIC DEMO]. */
  title: string;
  /** Short user-facing summary shown in the UI. */
  summary: string;
  /** The initial investigation prompt sent to the orchestrator. */
  initialPrompt: string;
}

export interface SyntheticDataset {
  scenarioId: ScenarioId;
  objective: ScenarioObjective;
  suspicion: ScenarioSuspicionLevel;
  hosts: Array<{ hostname: string; ip: string; os: string; role: string }>;
  users: Array<{ username: string; displayName: string; department: string; privileged: boolean }>;
  events: EventRecord[];
  processes: ProcessRecord[];
  networkConnections: NetworkConnectionRecord[];
  dnsQueries: DnsRecord[];
  identityActivity: IdentityActivityRecord[];
  fileAnalysisReports: FileAnalysisReport[];
  indicatorLookups: IndicatorLookupResult[];
}

export interface SyntheticScenario {
  id: ScenarioId;
  displayName: string;
  shortDescription: string;
  domain: string;
  difficulty: 'intro' | 'intermediate' | 'advanced';
  /** Build a fresh deterministic dataset for this scenario. */
  build(): SyntheticDataset;
}

export interface SyntheticEnvironmentStatus {
  loaded: boolean;
  scenarioId: ScenarioId | null;
  loadedAt: number | null;
  recordCounts: {
    events: number;
    processes: number;
    networkConnections: number;
    dnsQueries: number;
    identityActivity: number;
    fileAnalysisReports: number;
    indicatorLookups: number;
  };
}