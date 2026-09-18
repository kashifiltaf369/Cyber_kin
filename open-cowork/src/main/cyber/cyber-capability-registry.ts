import { createHash } from 'node:crypto';
import { existsSync, readFileSync, statSync, readdirSync } from 'node:fs';
import path from 'node:path';

export type CyberCapabilityName =
  | 'search_events'
  | 'search_processes'
  | 'search_network_connections'
  | 'search_dns'
  | 'search_identity_activity'
  | 'inspect_file'
  | 'calculate_hash'
  | 'lookup_indicator'
  | 'analyze_pcap'
  | 'search_historical_activity'
  | 'search_browser_data'
  | 'execute_safe_analysis'
  | 'query_local_logs';

export type CyberCapabilityRiskLevel = 'LOW' | 'MEDIUM' | 'HIGH';
export type CyberCapabilityCost = 'LOW' | 'MEDIUM' | 'HIGH';

export interface CyberCapabilityDefinition<Input = unknown, Output = unknown> {
  name: CyberCapabilityName;
  description: string;
  inputSchema: Record<string, unknown>;
  outputSchema: Record<string, unknown>;
  riskLevel: CyberCapabilityRiskLevel;
  permissionsRequired: string[];
  timeoutMs: number;
  cost: CyberCapabilityCost;
  supportedAdapters: string[];
  tags: string[];
  canAnswer: string[];
  actionCategory?: import('./cyber-permission-policy').CyberActionRiskCategory;
  executor: (input: Input, ctx?: CyberCapabilityExecutionContext) => Promise<Output>;
}

export interface CyberCapabilityExecutionContext {
  adapterPreference?: string;
  workspacePath?: string;
}

export interface CyberCapabilityDiscoveryResult {
  capability: CyberCapabilityDefinition;
  score: number;
  reasons: string[];
}

export interface EventSearchInput {
  sourcePath: string;
  query?: string;
  limit?: number;
}

export interface EventSearchOutput {
  sourcePath: string;
  matches: Array<{ lineNumber: number; line: string }>;
}

export interface ProcessSearchInput {
  sourcePath?: string;
  query?: string;
}

export interface ProcessSearchOutput {
  processes: Array<Record<string, unknown>>;
}

export interface NetworkSearchInput {
  sourcePath?: string;
  query?: string;
}

export interface NetworkSearchOutput {
  connections: Array<Record<string, unknown>>;
}

export interface DnsSearchInput {
  sourcePath: string;
  query?: string;
  limit?: number;
}

export interface DnsSearchOutput {
  records: Array<{ lineNumber: number; line: string }>;
}

export interface FileInspectInput {
  filePath: string;
}

export interface FileInspectOutput {
  path: string;
  exists: boolean;
  size: number | null;
  extension: string;
  preview: string;
}

export interface HashInput {
  filePath: string;
  algorithm?: 'md5' | 'sha1' | 'sha256';
}

export interface HashOutput {
  filePath: string;
  algorithm: 'md5' | 'sha1' | 'sha256';
  hash: string;
}

export interface IndicatorLookupInput {
  indicator: string;
}

export interface IndicatorLookupOutput {
  indicator: string;
  indicatorType: 'ip' | 'domain' | 'url' | 'hash' | 'unknown';
  summary: string;
  safeToEnrich: boolean;
}

export interface PcapAnalyzeInput {
  sourcePath: string;
  query?: string;
  limit?: number;
}

export interface PcapAnalyzeOutput {
  packets: Array<{ lineNumber: number; line: string }>;
}

export interface HistoricalSearchInput {
  sourcePath: string;
  query?: string;
  limit?: number;
}

export interface HistoricalSearchOutput {
  matches: Array<{ lineNumber: number; line: string }>;
}

export interface BrowserSearchInput {
  sourcePath: string;
  query?: string;
  limit?: number;
}

export interface BrowserSearchOutput {
  entries: Array<{ lineNumber: number; line: string }>;
}

export interface SafeAnalysisInput {
  sourcePath: string;
  query?: string;
  limit?: number;
}

export interface SafeAnalysisOutput {
  findings: Array<{ lineNumber: number; line: string }>;
}

export interface LocalLogsInput {
  directoryPath: string;
  query?: string;
  extensions?: string[];
  limit?: number;
}

export interface LocalLogsOutput {
  files: Array<{ path: string; matches: Array<{ lineNumber: number; line: string }> }>;
}

export class CyberCapabilityRegistry {
  private readonly definitions = new Map<CyberCapabilityName, CyberCapabilityDefinition>();

  constructor(definitions: CyberCapabilityDefinition[] = buildDefaultCapabilities()) {
    for (const definition of definitions) {
      this.definitions.set(definition.name, definition);
    }
  }

  list(): CyberCapabilityDefinition[] {
    return Array.from(this.definitions.values());
  }

  get(name: CyberCapabilityName): CyberCapabilityDefinition | null {
    return this.definitions.get(name) || null;
  }

  register(definition: CyberCapabilityDefinition): void {
    this.definitions.set(definition.name, definition);
  }

  unregister(name: CyberCapabilityName): boolean {
    return this.definitions.delete(name);
  }

  clear(): void {
    this.definitions.clear();
  }

  discover(question: string): CyberCapabilityDiscoveryResult[] {
    const normalized = normalize(question);
    return this.list()
      .map((capability) => {
        const reasons: string[] = [];
        let score = 0;
        for (const phrase of capability.canAnswer) {
          if (normalized.includes(normalize(phrase))) {
            score += 4;
            reasons.push(`matches phrase: ${phrase}`);
          }
        }
        for (const tag of capability.tags) {
          if (normalized.includes(normalize(tag))) {
            score += 2;
            reasons.push(`matches tag: ${tag}`);
          }
        }
        if (normalized.includes(normalize(capability.name.replace(/_/g, ' ')))) {
          score += 5;
          reasons.push(`matches capability name: ${capability.name}`);
        }
        return { capability, score, reasons };
      })
      .filter((item) => item.score > 0)
      .sort((a, b) => b.score - a.score || a.capability.name.localeCompare(b.capability.name));
  }

  discoverCapabilities(
    question: string,
    options: { limit?: number; minScore?: number } = {}
  ): CyberCapabilityDiscoveryResult[] {
    const limit = Math.max(1, options.limit ?? 10);
    const minScore = Math.max(0, options.minScore ?? 1);
    return this.discover(question)
      .filter((item) => item.score >= minScore)
      .slice(0, limit);
  }

  scoreCapability(
    capability: CyberCapabilityDefinition,
    subProblem: { title: string; description: string },
    probeResults?: Array<{ recommendedCapabilities: string[]; rejectedCapabilities: string[]; signal: string }>
  ): number {
    const text = `${subProblem.title} ${subProblem.description}`.toLowerCase();
    let score = 0;

    for (const phrase of capability.canAnswer) {
      if (text.includes(normalize(phrase))) score += 4;
    }
    for (const tag of capability.tags) {
      if (text.includes(normalize(tag))) score += 2;
    }
    if (text.includes(normalize(capability.name.replace(/_/g, ' ')))) score += 5;

    if (probeResults) {
      const recommended = probeResults.filter((r) => r.signal === 'POSITIVE').length;
      const rejected = probeResults.filter((r) => r.signal === 'NEGATIVE').length;
      score += recommended * 3;
      score -= rejected * 2;
    }

    const riskPenalty = capability.riskLevel === 'HIGH' ? 2 : capability.riskLevel === 'MEDIUM' ? 1 : 0;
    score -= riskPenalty;

    return Math.max(0, score);
  }

  async execute<Name extends CyberCapabilityName>(
    name: Name,
    input: unknown,
    ctx?: CyberCapabilityExecutionContext
  ): Promise<unknown> {
    const capability = this.get(name);
    if (!capability) {
      throw new Error(`Unknown capability: ${name}`);
    }
    return capability.executor(input, ctx);
  }
}

function buildDefaultCapabilities(): CyberCapabilityDefinition[] {
  return [
    {
      name: 'search_events',
      description: 'Search local event-style logs for matching security-relevant records.',
      inputSchema: {
        type: 'object',
        required: ['sourcePath'],
        properties: { sourcePath: { type: 'string' }, query: { type: 'string' }, limit: { type: 'number' } },
      },
      outputSchema: { type: 'object', properties: { sourcePath: { type: 'string' }, matches: { type: 'array' } } },
      riskLevel: 'LOW',
      permissionsRequired: ['filesystem:read'],
      timeoutMs: 30000,
      cost: 'LOW',
      supportedAdapters: ['local-file-grep'],
      tags: ['events', 'logs', 'security event', 'windows event', 'linux auth'],
      canAnswer: ['search authentication events', 'find suspicious event logs'],
      executor: async (input) => grepFileLines(input as unknown as EventSearchInput),
    },
    {
      name: 'search_processes',
      description: 'Search local process snapshots or process-list style data.',
      inputSchema: { type: 'object', properties: { sourcePath: { type: 'string' }, query: { type: 'string' } } },
      outputSchema: { type: 'object', properties: { processes: { type: 'array' } } },
      riskLevel: 'LOW',
      permissionsRequired: ['filesystem:read'],
      timeoutMs: 15000,
      cost: 'LOW',
      supportedAdapters: ['json-process-snapshot', 'csv-process-snapshot'],
      tags: ['process', 'powershell', 'cmd', 'execution', 'parent process'],
      canAnswer: ['what processes were running', 'search process execution'],
      executor: async (input) => searchStructuredRecords(input as unknown as ProcessSearchInput),
    },
    {
      name: 'search_network_connections',
      description: 'Search local network connection snapshots or connection logs.',
      inputSchema: { type: 'object', properties: { sourcePath: { type: 'string' }, query: { type: 'string' } } },
      outputSchema: { type: 'object', properties: { connections: { type: 'array' } } },
      riskLevel: 'LOW',
      permissionsRequired: ['filesystem:read'],
      timeoutMs: 15000,
      cost: 'LOW',
      supportedAdapters: ['json-network-snapshot', 'csv-network-snapshot'],
      tags: ['network', 'connection', 'egress', 'port', 'lateral movement'],
      canAnswer: ['search network connections', 'find suspicious connections'],
      executor: async (input) => searchStructuredRecords(input as unknown as NetworkSearchInput, 'connections'),
    },
    {
      name: 'search_dns',
      description: 'Search DNS query logs or DNS-derived text exports.',
      inputSchema: {
        type: 'object',
        required: ['sourcePath'],
        properties: { sourcePath: { type: 'string' }, query: { type: 'string' }, limit: { type: 'number' } },
      },
      outputSchema: { type: 'object', properties: { records: { type: 'array' } } },
      riskLevel: 'LOW',
      permissionsRequired: ['filesystem:read'],
      timeoutMs: 20000,
      cost: 'LOW',
      supportedAdapters: ['local-file-grep'],
      tags: ['dns', 'domain', 'resolver', 'query'],
      canAnswer: ['search dns queries', 'find domain lookups'],
      executor: async (input) => {
        const result = await grepFileLines(input as unknown as DnsSearchInput);
        return { records: result.matches } as DnsSearchOutput;
      },
    },
    {
      name: 'search_identity_activity',
      description: 'Search local identity and authentication activity exports.',
      inputSchema: {
        type: 'object',
        required: ['sourcePath'],
        properties: { sourcePath: { type: 'string' }, query: { type: 'string' }, limit: { type: 'number' } },
      },
      outputSchema: { type: 'object', properties: { sourcePath: { type: 'string' }, matches: { type: 'array' } } },
      riskLevel: 'LOW',
      permissionsRequired: ['filesystem:read'],
      timeoutMs: 20000,
      cost: 'LOW',
      supportedAdapters: ['local-file-grep'],
      tags: ['identity', 'authentication', 'signin', 'mfa', 'account'],
      canAnswer: ['search identity activity', 'find suspicious sign-ins'],
      executor: async (input) => grepFileLines(input as unknown as EventSearchInput),
    },
    {
      name: 'inspect_file',
      description: 'Inspect a local file safely, including metadata and preview text.',
      inputSchema: { type: 'object', required: ['filePath'], properties: { filePath: { type: 'string' } } },
      outputSchema: { type: 'object', properties: { path: { type: 'string' }, exists: { type: 'boolean' } } },
      riskLevel: 'LOW',
      permissionsRequired: ['filesystem:read'],
      timeoutMs: 10000,
      cost: 'LOW',
      supportedAdapters: ['local-file-inspector'],
      tags: ['file', 'artifact', 'document', 'binary'],
      canAnswer: ['inspect this file', 'what is this artifact'],
      executor: async (input) => inspectFile(input as unknown as FileInspectInput),
    },
    {
      name: 'calculate_hash',
      description: 'Calculate a cryptographic hash for a local file.',
      inputSchema: {
        type: 'object',
        required: ['filePath'],
        properties: { filePath: { type: 'string' }, algorithm: { type: 'string' } },
      },
      outputSchema: { type: 'object', properties: { filePath: { type: 'string' }, algorithm: { type: 'string' }, hash: { type: 'string' } } },
      riskLevel: 'LOW',
      permissionsRequired: ['filesystem:read'],
      timeoutMs: 10000,
      cost: 'LOW',
      supportedAdapters: ['node-crypto-local'],
      tags: ['hash', 'sha256', 'sha1', 'md5', 'indicator'],
      canAnswer: ['calculate hash', 'hash this file'],
      executor: async (input) => calculateHash(input as unknown as HashInput),
    },
    {
      name: 'lookup_indicator',
      description: 'Perform safe, local-only indicator classification and enrichment suitability checks.',
      inputSchema: { type: 'object', required: ['indicator'], properties: { indicator: { type: 'string' } } },
      outputSchema: { type: 'object', properties: { indicator: { type: 'string' }, indicatorType: { type: 'string' }, safeToEnrich: { type: 'boolean' } } },
      riskLevel: 'LOW',
      permissionsRequired: [],
      timeoutMs: 5000,
      cost: 'LOW',
      supportedAdapters: ['local-classifier'],
      tags: ['indicator', 'ioc', 'domain', 'ip', 'hash', 'url'],
      canAnswer: ['lookup indicator', 'what type of indicator is this'],
      executor: async (input) => lookupIndicator(input as unknown as IndicatorLookupInput),
    },
    {
      name: 'analyze_pcap',
      description: 'Analyze text-exported PCAP summaries or packet metadata exports safely.',
      inputSchema: {
        type: 'object',
        required: ['sourcePath'],
        properties: { sourcePath: { type: 'string' }, query: { type: 'string' }, limit: { type: 'number' } },
      },
      outputSchema: { type: 'object', properties: { packets: { type: 'array' } } },
      riskLevel: 'LOW',
      permissionsRequired: ['filesystem:read'],
      timeoutMs: 30000,
      cost: 'MEDIUM',
      supportedAdapters: ['pcap-text-export'],
      tags: ['pcap', 'packet', 'wireshark', 'network capture'],
      canAnswer: ['analyze pcap', 'search packet capture'],
      executor: async (input) => {
        const result = await grepFileLines(input as unknown as PcapAnalyzeInput);
        return { packets: result.matches } as PcapAnalyzeOutput;
      },
    },
    {
      name: 'search_historical_activity',
      description: 'Search historical activity snapshots or baselines.',
      inputSchema: {
        type: 'object',
        required: ['sourcePath'],
        properties: { sourcePath: { type: 'string' }, query: { type: 'string' }, limit: { type: 'number' } },
      },
      outputSchema: { type: 'object', properties: { matches: { type: 'array' } } },
      riskLevel: 'LOW',
      permissionsRequired: ['filesystem:read'],
      timeoutMs: 20000,
      cost: 'LOW',
      supportedAdapters: ['local-file-grep'],
      tags: ['historical', 'baseline', 'previous activity', 'legitimate'],
      canAnswer: ['search historical activity', 'compare against baseline'],
      executor: async (input) => {
        const result = await grepFileLines(input as unknown as HistoricalSearchInput);
        return { matches: result.matches } as HistoricalSearchOutput;
      },
    },
    {
      name: 'search_browser_data',
      description: 'Search browser history exports, downloads, or text-derived browser records.',
      inputSchema: {
        type: 'object',
        required: ['sourcePath'],
        properties: { sourcePath: { type: 'string' }, query: { type: 'string' }, limit: { type: 'number' } },
      },
      outputSchema: { type: 'object', properties: { entries: { type: 'array' } } },
      riskLevel: 'LOW',
      permissionsRequired: ['filesystem:read'],
      timeoutMs: 20000,
      cost: 'LOW',
      supportedAdapters: ['local-file-grep'],
      tags: ['browser', 'history', 'downloads', 'url'],
      canAnswer: ['search browser data', 'find browser history'],
      executor: async (input) => {
        const result = await grepFileLines(input as unknown as BrowserSearchInput);
        return { entries: result.matches } as BrowserSearchOutput;
      },
    },
    {
      name: 'execute_safe_analysis',
      description: 'Run safe, non-destructive analysis over local text-based artifacts.',
      inputSchema: {
        type: 'object',
        required: ['sourcePath'],
        properties: { sourcePath: { type: 'string' }, query: { type: 'string' }, limit: { type: 'number' } },
      },
      outputSchema: { type: 'object', properties: { findings: { type: 'array' } } },
      riskLevel: 'MEDIUM',
      permissionsRequired: ['filesystem:read', 'analysis:safe-only'],
      timeoutMs: 30000,
      cost: 'MEDIUM',
      supportedAdapters: ['local-file-grep'],
      tags: ['analysis', 'safe', 'artifact triage', 'review'],
      canAnswer: ['run safe analysis', 'analyze local evidence safely'],
      executor: async (input) => {
        const result = await grepFileLines(input as unknown as SafeAnalysisInput);
        return { findings: result.matches } as SafeAnalysisOutput;
      },
    },
    {
      name: 'query_local_logs',
      description: 'Query a directory of local log files without relying on a vendor backend.',
      inputSchema: {
        type: 'object',
        required: ['directoryPath'],
        properties: {
          directoryPath: { type: 'string' },
          query: { type: 'string' },
          extensions: { type: 'array' },
          limit: { type: 'number' },
        },
      },
      outputSchema: { type: 'object', properties: { files: { type: 'array' } } },
      riskLevel: 'LOW',
      permissionsRequired: ['filesystem:read'],
      timeoutMs: 45000,
      cost: 'MEDIUM',
      supportedAdapters: ['local-log-directory'],
      tags: ['logs', 'directory', 'windows logs', 'linux logs', 'local evidence'],
      canAnswer: ['query local logs', 'search all local logs in a folder'],
      executor: async (input) => queryLocalLogs(input as unknown as LocalLogsInput),
    },
  ];
}

async function grepFileLines(input: EventSearchInput): Promise<EventSearchOutput> {
  ensureFileExists(input.sourcePath);
  const content = readFileSync(input.sourcePath, 'utf8');
  const limit = Math.max(1, input.limit || 50);
  const query = normalize(input.query || '');
  const matches = content
    .split(/\r?\n/)
    .map((line, index) => ({ lineNumber: index + 1, line }))
    .filter((item) => (query ? normalize(item.line).includes(query) : item.line.trim().length > 0))
    .slice(0, limit);
  return { sourcePath: input.sourcePath, matches };
}

async function searchStructuredRecords(
  input: ProcessSearchInput | NetworkSearchInput,
  collectionKey?: 'connections'
): Promise<ProcessSearchOutput | NetworkSearchOutput> {
  if (!input.sourcePath) {
    return collectionKey ? { connections: [] } : { processes: [] };
  }
  ensureFileExists(input.sourcePath);
  const records = readStructuredRecords(input.sourcePath);
  const query = normalize(input.query || '');
  const filtered = query
    ? records.filter((record) => normalize(JSON.stringify(record)).includes(query))
    : records;
  return collectionKey ? { connections: filtered } : { processes: filtered };
}

function readStructuredRecords(sourcePath: string): Array<Record<string, unknown>> {
  const ext = path.extname(sourcePath).toLowerCase();
  const content = readFileSync(sourcePath, 'utf8');
  if (ext === '.json') {
    const parsed: unknown = JSON.parse(content);
    if (Array.isArray(parsed)) return parsed.filter(isRecord);
    if (isRecord(parsed)) {
      for (const key of ['processes', 'connections', 'items', 'records']) {
        const value = parsed[key];
        if (Array.isArray(value)) {
          return value.filter(isRecord);
        }
      }
      return [parsed];
    }
    return [];
  }
  if (ext === '.csv') {
    const lines = content.split(/\r?\n/).filter(Boolean);
    if (lines.length === 0) return [];
    const headers = lines[0].split(',').map((item) => item.trim());
    return lines.slice(1).map((line) => {
      const values = line.split(',');
      return headers.reduce<Record<string, unknown>>((acc, header, index) => {
        acc[header] = (values[index] || '').trim();
        return acc;
      }, {});
    });
  }
  return content
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => ({ line }));
}

async function inspectFile(input: FileInspectInput): Promise<FileInspectOutput> {
  if (!existsSync(input.filePath)) {
    return { path: input.filePath, exists: false, size: null, extension: path.extname(input.filePath), preview: '' };
  }
  const stats = statSync(input.filePath);
  const preview = readFileSync(input.filePath, 'utf8').slice(0, 500);
  return {
    path: input.filePath,
    exists: true,
    size: stats.size,
    extension: path.extname(input.filePath).toLowerCase(),
    preview,
  };
}

async function calculateHash(input: HashInput): Promise<HashOutput> {
  ensureFileExists(input.filePath);
  const algorithm = input.algorithm || 'sha256';
  const hash = createHash(algorithm).update(readFileSync(input.filePath)).digest('hex');
  return { filePath: input.filePath, algorithm, hash };
}

async function lookupIndicator(input: IndicatorLookupInput): Promise<IndicatorLookupOutput> {
  const indicator = input.indicator.trim();
  const indicatorType = classifyIndicator(indicator);
  return {
    indicator,
    indicatorType,
    summary: `Local classification for ${indicatorType} indicator. No vendor enrichment performed.`,
    safeToEnrich: indicatorType !== 'unknown',
  };
}

async function queryLocalLogs(input: LocalLogsInput): Promise<LocalLogsOutput> {
  if (!existsSync(input.directoryPath)) {
    throw new Error(`Directory not found: ${input.directoryPath}`);
  }
  const extensions = new Set((input.extensions || ['.log', '.txt', '.json', '.evtx.txt']).map((item) => item.toLowerCase()));
  const files = walkFiles(input.directoryPath).filter(
    (file) => extensions.size === 0 || extensions.has(path.extname(file).toLowerCase())
  );
  const results: LocalLogsOutput['files'] = [];
  const limit = Math.max(1, input.limit || 20);
  for (const file of files) {
    const matches = (await grepFileLines({ sourcePath: file, query: input.query, limit })).matches;
    if (matches.length > 0) {
      results.push({ path: file, matches });
    }
    if (results.length >= limit) break;
  }
  return { files: results };
}

function walkFiles(dir: string): string[] {
  const results: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkFiles(full));
    } else {
      results.push(full);
    }
  }
  return results;
}

function ensureFileExists(filePath: string): void {
  if (!existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }
}

function classifyIndicator(value: string): IndicatorLookupOutput['indicatorType'] {
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';
  if (/^https?:\/\//i.test(value)) return 'url';
  if (/^[a-f0-9]{32}$/i.test(value) || /^[a-f0-9]{40}$/i.test(value) || /^[a-f0-9]{64}$/i.test(value)) return 'hash';
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) return 'domain';
  return 'unknown';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function normalize(value: string): string {
  return value.toLowerCase().trim();
}
