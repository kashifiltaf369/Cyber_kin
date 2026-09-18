/**
 * @module main/integrations/integration-types
 *
 * Vendor-neutral integration boundary contracts.
 *
 * Every external system the investigation engine talks to (SIEM, EDR,
 * network telemetry, identity provider, threat intelligence, file analysis,
 * cloud logs) is reached through one of these interfaces. Vendor-specific
 * implementations live behind adapters and never leak into the core
 * investigation engine.
 *
 * Per CYBER_BUILD_RULES rule 13 (evidence must have provenance), every
 * observation returned by an adapter carries a `provenance` block identifying
 * the source system, adapter id, capability, and collection method.
 */

export type IntegrationDomain =
  | 'siem'
  | 'edr'
  | 'network'
  | 'identity'
  | 'threat-intel'
  | 'file-analysis'
  | 'cloud-logs';

export const INTEGRATION_DOMAINS: readonly IntegrationDomain[] = [
  'siem',
  'edr',
  'network',
  'identity',
  'threat-intel',
  'file-analysis',
  'cloud-logs',
] as const;

export interface IntegrationProvenance {
  domain: IntegrationDomain;
  adapterId: string;
  vendor: string;
  capability: string;
  method: 'api_query' | 'log_export' | 'file_import' | 'stream' | 'sdk_call';
  collectedAt: number;
  sourceLabel?: string;
  sourceId?: string;
  investigationId?: string | null;
}

export interface IntegrationObservation<T = unknown> {
  value: T;
  provenance: IntegrationProvenance;
}

export interface IntegrationCapabilities {
  searchEvents?: boolean;
  searchProcesses?: boolean;
  searchNetworkConnections?: boolean;
  searchDns?: boolean;
  searchIdentityActivity?: boolean;
  lookupIndicator?: boolean;
  submitFileForAnalysis?: boolean;
  fetchFileReport?: boolean;
  queryCloudLogs?: boolean;
}

export interface IntegrationMetadata {
  domain: IntegrationDomain;
  vendor: string;
  adapterId: string;
  displayName: string;
  description: string;
  capabilities: IntegrationCapabilities;
}

export interface IntegrationHealth {
  available: boolean;
  reason?: string;
  missingRequirements?: string[];
  checkedAt: number;
}

export interface EventSearchQuery {
  query?: string;
  startTime?: number;
  endTime?: number;
  limit?: number;
  filters?: Record<string, string | number | boolean>;
}

export interface EventRecord {
  id: string;
  timestamp: number;
  source: string;
  severity?: string;
  message: string;
  raw?: Record<string, unknown>;
}

export interface ProcessRecord {
  id: string;
  host?: string;
  pid?: number;
  name: string;
  commandLine?: string;
  parentName?: string;
  parentPid?: number;
  user?: string;
  startTime?: number;
  raw?: Record<string, unknown>;
}

export interface NetworkConnectionRecord {
  id: string;
  host?: string;
  processName?: string;
  pid?: number;
  localAddress?: string;
  remoteAddress: string;
  remotePort?: number;
  protocol?: string;
  timestamp?: number;
  raw?: Record<string, unknown>;
}

export interface DnsRecord {
  id: string;
  host?: string;
  timestamp?: number;
  query: string;
  queryType?: string;
  response?: string;
  raw?: Record<string, unknown>;
}

export interface IdentityActivityRecord {
  id: string;
  actor: string;
  action: string;
  target?: string;
  timestamp: number;
  source?: string;
  ipAddress?: string;
  result?: 'success' | 'failure' | 'unknown';
  raw?: Record<string, unknown>;
}

export interface IndicatorLookupResult {
  indicator: string;
  indicatorType: 'ip' | 'domain' | 'url' | 'hash' | 'unknown';
  verdict?: 'malicious' | 'suspicious' | 'benign' | 'unknown';
  confidence?: number;
  categories?: string[];
  sources?: string[];
  firstSeen?: number;
  lastSeen?: number;
  raw?: Record<string, unknown>;
}

export interface FileAnalysisSubmission {
  fileName: string;
  contentType?: string;
  size?: number;
  contentRef: string;
  hash?: string;
}

export interface FileAnalysisReport {
  submissionId: string;
  status: 'queued' | 'running' | 'complete' | 'error';
  verdict?: 'malicious' | 'suspicious' | 'benign' | 'unknown';
  score?: number;
  engines?: Array<{ name: string; verdict: string }>;
  completedAt?: number;
  raw?: Record<string, unknown>;
}

export interface CloudLogQuery {
  service?: string;
  eventName?: string;
  startTime?: number;
  endTime?: number;
  limit?: number;
  filters?: Record<string, string | number | boolean>;
}

export interface CloudLogRecord {
  id: string;
  timestamp: number;
  service: string;
  eventName: string;
  actor?: string;
  resource?: string;
  sourceIp?: string;
  raw?: Record<string, unknown>;
}

export interface SiemAdapter {
  readonly metadata: IntegrationMetadata;
  health(): Promise<IntegrationHealth>;
  searchEvents(query: EventSearchQuery): Promise<IntegrationObservation<EventRecord[]>>;
}

export interface EdrAdapter {
  readonly metadata: IntegrationMetadata;
  health(): Promise<IntegrationHealth>;
  searchProcesses(query: EventSearchQuery & { host?: string; name?: string }): Promise<IntegrationObservation<ProcessRecord[]>>;
  searchNetworkConnections(query: EventSearchQuery & { host?: string; remoteAddress?: string }): Promise<IntegrationObservation<NetworkConnectionRecord[]>>;
  searchDns?(query: EventSearchQuery & { host?: string; name?: string }): Promise<IntegrationObservation<DnsRecord[]>>;
}

export interface NetworkTelemetryAdapter {
  readonly metadata: IntegrationMetadata;
  health(): Promise<IntegrationHealth>;
  searchConnections(query: EventSearchQuery & { remoteAddress?: string; host?: string }): Promise<IntegrationObservation<NetworkConnectionRecord[]>>;
  searchDns(query: EventSearchQuery & { host?: string; name?: string }): Promise<IntegrationObservation<DnsRecord[]>>;
}

export interface IdentityAdapter {
  readonly metadata: IntegrationMetadata;
  health(): Promise<IntegrationHealth>;
  queryIdentityActivity(query: EventSearchQuery & { actor?: string; action?: string }): Promise<IntegrationObservation<IdentityActivityRecord[]>>;
}

export interface ThreatIntelAdapter {
  readonly metadata: IntegrationMetadata;
  health(): Promise<IntegrationHealth>;
  lookupIndicator(indicator: string): Promise<IntegrationObservation<IndicatorLookupResult>>;
}

export interface FileAnalysisAdapter {
  readonly metadata: IntegrationMetadata;
  health(): Promise<IntegrationHealth>;
  submitFileForAnalysis(submission: FileAnalysisSubmission): Promise<IntegrationObservation<FileAnalysisReport>>;
  fetchFileReport(submissionId: string): Promise<IntegrationObservation<FileAnalysisReport>>;
}

export interface CloudLogsAdapter {
  readonly metadata: IntegrationMetadata;
  health(): Promise<IntegrationHealth>;
  queryCloudLogs(query: CloudLogQuery): Promise<IntegrationObservation<CloudLogRecord[]>>;
}

export type AnyIntegrationAdapter =
  | SiemAdapter
  | EdrAdapter
  | NetworkTelemetryAdapter
  | IdentityAdapter
  | ThreatIntelAdapter
  | FileAnalysisAdapter
  | CloudLogsAdapter;

export function isSiemAdapter(value: AnyIntegrationAdapter): value is SiemAdapter {
  return value.metadata.domain === 'siem';
}

export function isEdrAdapter(value: AnyIntegrationAdapter): value is EdrAdapter {
  return value.metadata.domain === 'edr';
}

export function isNetworkTelemetryAdapter(value: AnyIntegrationAdapter): value is NetworkTelemetryAdapter {
  return value.metadata.domain === 'network';
}

export function isIdentityAdapter(value: AnyIntegrationAdapter): value is IdentityAdapter {
  return value.metadata.domain === 'identity';
}

export function isThreatIntelAdapter(value: AnyIntegrationAdapter): value is ThreatIntelAdapter {
  return value.metadata.domain === 'threat-intel';
}

export function isFileAnalysisAdapter(value: AnyIntegrationAdapter): value is FileAnalysisAdapter {
  return value.metadata.domain === 'file-analysis';
}

export function isCloudLogsAdapter(value: AnyIntegrationAdapter): value is CloudLogsAdapter {
  return value.metadata.domain === 'cloud-logs';
}
