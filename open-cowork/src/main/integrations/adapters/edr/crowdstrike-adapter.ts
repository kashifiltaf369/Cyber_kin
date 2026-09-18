/**
 * @module main/integrations/adapters/edr/crowdstrike-adapter
 *
 * CrowdStrike Falcon EDR adapter. Uses Falcon Flight Control-style REST
 * endpoints (processes, network connections, DNS) to satisfy the EDR
 * capability set.
 */

import type { AdapterFactory } from '../../integration-registry';
import type { IntegrationCredentialResolver } from '../../integration-credentials';
import type { DnsRecord, EdrAdapter, EventSearchQuery, IntegrationMetadata, IntegrationObservation, NetworkConnectionRecord, ProcessRecord } from '../../integration-types';
import { resolveCredential } from '../../integration-registry';
import { adapterFetch } from '../adapter-http-client';

export const CROWDSTRIKE_METADATA: IntegrationMetadata = {
  domain: 'edr',
  vendor: 'crowdstrike',
  adapterId: 'crowdstrike-falcon',
  displayName: 'CrowdStrike Falcon',
  description: 'Query processes, network connections, and DNS via the CrowdStrike Falcon API.',
  capabilities: { searchProcesses: true, searchNetworkConnections: true, searchDns: true },
};

interface CrowdStrikeResponse<T> {
  resources?: T[];
  errors?: Array<{ message?: string }>;
}interface CrowdStrikeProcess {
  process_id?: string;
  image_filename?: string;
  command_line?: string;
  parent_process_id?: string;
  parent_image_filename?: string;
  username?: string;
  start_timestamp?: string;
  device_hostname?: string;
}

interface CrowdStrikeConnection {
  remote_address?: string;
  remote_port?: number;
  local_address?: string;
  protocol?: string;
  process_image_filename?: string;
  device_hostname?: string;
  timestamp?: string;
}

interface CrowdStrikeDns {
  domain?: string;
  query_type?: string;
  response?: string;
  device_hostname?: string;
  timestamp?: string;
}

export class CrowdStrikeEdrAdapter implements EdrAdapter {
  readonly metadata = CROWDSTRIKE_METADATA;

  constructor(
    private readonly baseUrl: string,
    private readonly token: string
  ) {}

  async health() {
    try {
      await adapterFetch({
        url: `${this.baseUrl.replace(/\/$/, '')}/sensors/queries/installed-base/v1`,
        method: 'GET',
        headers: { Authorization: `Bearer ${this.token}` },
        timeoutMs: 5000,
      });
      return { available: true, checkedAt: Date.now() };
    } catch (error) {
      return {
        available: false,
        reason: error instanceof Error ? error.message : 'CrowdStrike health check failed',
        checkedAt: Date.now(),
      };
    }
  }

  async searchProcesses(query: EventSearchQuery & { host?: string; name?: string }): Promise<IntegrationObservation<ProcessRecord[]>> {
    const filter = buildFilter([
      query.host ? `device_hostname:*${sanitize(query.host)}*` : null,
      query.name ? `image_filename:*${sanitize(query.name)}*` : null,
      query.query ? `command_line:*${sanitize(query.query)}*` : null,
    ]);
    const response = await adapterFetch<CrowdStrikeResponse<string>>({
      url: `${this.baseUrl.replace(/\/$/, '')}/processes/queries/processes/v1`,
      method: 'GET',
      headers: { Authorization: `Bearer ${this.token}` },
      timeoutMs: 15_000,
    });
    const ids = (response.data.resources || []).filter((id): id is string => typeof id === 'string');
    const detail = await this.fetchDetails<CrowdStrikeProcess>('/processes/entities/processes/v1', ids);
    const processes = detail
      .filter((process) => (filter ? matches(process as unknown as Record<string, unknown>, filter) : true))
      .map((process, index) => normalizeProcess(process, index));
    return {
      value: processes,
      provenance: provenance(this.metadata, 'searchProcesses'),
    };
  }

  async searchNetworkConnections(query: EventSearchQuery & { host?: string; remoteAddress?: string }): Promise<IntegrationObservation<NetworkConnectionRecord[]>> {
    const response = await adapterFetch<CrowdStrikeResponse<string>>({
      url: `${this.baseUrl.replace(/\/$/, '')}/networks/queries/connections/v1`,
      method: 'GET',
      headers: { Authorization: `Bearer ${this.token}` },
      timeoutMs: 15_000,
    });
    const ids = (response.data.resources || []).filter((id): id is string => typeof id === 'string');
    const detail = await this.fetchDetails<CrowdStrikeConnection>('/networks/entities/connections/v1', ids);
    const connections = detail
      .filter((conn) => !query.remoteAddress || conn.remote_address === query.remoteAddress)
      .filter((conn) => !query.host || conn.device_hostname === query.host)
      .map((conn, index) => normalizeConnection(conn, index));
    return {
      value: connections,
      provenance: provenance(this.metadata, 'searchNetworkConnections'),
    };
  }

  async searchDns(query: EventSearchQuery & { host?: string; name?: string }): Promise<IntegrationObservation<DnsRecord[]>> {
    const response = await adapterFetch<CrowdStrikeResponse<string>>({
      url: `${this.baseUrl.replace(/\/$/, '')}/networks/queries/dns/v1`,
      method: 'GET',
      headers: { Authorization: `Bearer ${this.token}` },
      timeoutMs: 15_000,
    });
    const ids = (response.data.resources || []).filter((id): id is string => typeof id === 'string');
    const detail = await this.fetchDetails<CrowdStrikeDns>('/networks/entities/dns/v1', ids);
    const records = detail
      .filter((dns) => !query.name || dns.domain?.includes(query.name))
      .filter((dns) => !query.host || dns.device_hostname === query.host)
      .map((dns, index) => normalizeDns(dns, index));
    return {
      value: records,
      provenance: provenance(this.metadata, 'searchDns'),
    };
  }

  private async fetchDetails<T>(path: string, ids: string[]): Promise<T[]> {
    if (ids.length === 0) return [];
    const response = await adapterFetch<CrowdStrikeResponse<T>>({
      url: `${this.baseUrl.replace(/\/$/, '')}${path}?ids=${ids.slice(0, 100).map(encodeURIComponent).join(',')}`,
      method: 'GET',
      headers: { Authorization: `Bearer ${this.token}` },
      timeoutMs: 15_000,
    });
    return response.data.resources || [];
  }
}

function buildFilter(parts: Array<string | null>): string | null {
  const filtered = parts.filter(Boolean);
  return filtered.length === 0 ? null : filtered.join('+');
}

function matches(record: Record<string, unknown>, filter: string): boolean {
  const clauses = filter.split('+').filter(Boolean);
  return clauses.every((clause) => {
    const [key, value] = clause.split(':');
    const needle = value.replace(/^\*|\*$/g, '');
    const haystack = String(record[key] || '');
    return haystack.includes(needle);
  });
}

function sanitize(input: string): string {
  return input.replace(/[^\w.@-]/g, '').slice(0, 200);
}

function normalizeProcess(process: CrowdStrikeProcess, index: number): ProcessRecord {
  return {
    id: process.process_id || `crowdstrike-proc-${index}`,
    host: process.device_hostname,
    name: process.image_filename || 'unknown',
    commandLine: process.command_line,
    parentName: process.parent_image_filename,
    parentPid: process.parent_process_id ? Number(process.parent_process_id) : undefined,
    user: process.username,
    startTime: process.start_timestamp ? Date.parse(process.start_timestamp) : undefined,
    raw: process as unknown as Record<string, unknown>,
  };
}

function normalizeConnection(conn: CrowdStrikeConnection, index: number): NetworkConnectionRecord {
  return {
    id: `crowdstrike-conn-${index}-${conn.remote_address}`,
    host: conn.device_hostname,
    processName: conn.process_image_filename,
    remoteAddress: conn.remote_address || '',
    remotePort: conn.remote_port,
    localAddress: conn.local_address,
    protocol: conn.protocol,
    timestamp: conn.timestamp ? Date.parse(conn.timestamp) : undefined,
    raw: conn as unknown as Record<string, unknown>,
  };
}

function normalizeDns(dns: CrowdStrikeDns, index: number): DnsRecord {
  return {
    id: `crowdstrike-dns-${index}-${dns.domain}`,
    host: dns.device_hostname,
    query: dns.domain || '',
    queryType: dns.query_type,
    response: dns.response,
    timestamp: dns.timestamp ? Date.parse(dns.timestamp) : undefined,
    raw: dns as unknown as Record<string, unknown>,
  };
}

function provenance(metadata: IntegrationMetadata, capability: string) {
  return {
    domain: 'edr' as const,
    adapterId: metadata.adapterId,
    vendor: metadata.vendor,
    capability,
    method: 'api_query' as const,
    collectedAt: Date.now(),
  };
}

export function createCrowdStrikeFactory(): AdapterFactory {
  return {
    domain: 'edr',
    vendor: 'crowdstrike',
    adapterId: 'crowdstrike-falcon',
    requiredCredentials: [
      { envVar: 'CROWDSTRIKE_BASE_URL', configKey: 'baseUrl' },
      { envVar: 'CROWDSTRIKE_TOKEN', configKey: 'token' },
    ],
    build(resolver: IntegrationCredentialResolver) {
      const baseUrl = resolveCredential(resolver, 'edr', 'crowdstrike', 'CROWDSTRIKE_BASE_URL', 'baseUrl').value;
      const token = resolveCredential(resolver, 'edr', 'crowdstrike', 'CROWDSTRIKE_TOKEN', 'token').value;
      return new CrowdStrikeEdrAdapter(baseUrl, token);
    },
  };
}
