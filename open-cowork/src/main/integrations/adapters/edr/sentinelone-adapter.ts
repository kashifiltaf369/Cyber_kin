/**
 * @module main/integrations/adapters/edr/sentinelone-adapter
 *
 * SentinelOne Singularity XDR adapter (read-only).
 */

import type { AdapterFactory } from '../../integration-registry';
import type { IntegrationCredentialResolver } from '../../integration-credentials';
import type { DnsRecord, EdrAdapter, EventSearchQuery, IntegrationMetadata, IntegrationObservation, NetworkConnectionRecord, ProcessRecord } from '../../integration-types';
import { resolveCredential } from '../../integration-registry';
import { adapterFetch } from '../adapter-http-client';

export const SENTINELONE_METADATA: IntegrationMetadata = {
  domain: 'edr',
  vendor: 'sentinelone',
  adapterId: 'sentinelone-singularity',
  displayName: 'SentinelOne Singularity',
  description: 'Read-only SentinelOne deep visibility queries for processes, network, and DNS.',
  capabilities: { searchProcesses: true, searchNetworkConnections: true, searchDns: true },
};

interface SentinelOneResponse<T> {
  data?: T[];
  errors?: Array<{ message?: string }>;
}

interface SentinelOneProcess {
  id?: string;
  agentComputerName?: string;
  processName?: string;
  cmdLine?: string;
  parentProcessName?: string;
  pid?: number;
  parentPid?: number;
  startTime?: string;
  user?: string;
}

interface SentinelOneConnection {
  id?: string;
  agentComputerName?: string;
  processName?: string;
  dstIp?: string;
  dstPort?: number;
  srcIp?: string;
  protocol?: string;
  timestamp?: string;
}

interface SentinelOneDns {
  id?: string;
  agentComputerName?: string;
  domainName?: string;
  queryType?: string;
  answer?: string;
  timestamp?: string;
}

export class SentinelOneEdrAdapter implements EdrAdapter {
  readonly metadata = SENTINELONE_METADATA;

  constructor(
    private readonly baseUrl: string,
    private readonly token: string
  ) {}

  async health() {
    try {
      await adapterFetch({
        url: `${this.baseUrl.replace(/\/$/, '')}/web/api/v2.1/system/status`,
        method: 'GET',
        headers: { Authorization: `ApiToken ${this.token}` },
        timeoutMs: 5000,
      });
      return { available: true, checkedAt: Date.now() };
    } catch (error) {
      return {
        available: false,
        reason: error instanceof Error ? error.message : 'SentinelOne health check failed',
        checkedAt: Date.now(),
      };
    }
  }

  async searchProcesses(query: EventSearchQuery & { host?: string; name?: string }): Promise<IntegrationObservation<ProcessRecord[]>> {
    const filter = [
      query.host ? `agentComputerName.contains='${sanitize(query.host)}'` : null,
      query.name ? `processName.contains='${sanitize(query.name)}'` : null,
      query.query ? `cmdLine.contains='${sanitize(query.query)}'` : null,
    ].filter(Boolean).join(' AND ') || null;
    const response = await adapterFetch<SentinelOneResponse<SentinelOneProcess>>({
      url: `${this.baseUrl.replace(/\/$/, '')}/web/api/v2.1/processes`,
      method: 'POST',
      headers: { Authorization: `ApiToken ${this.token}` },
      body: { filter, limit: Math.max(1, query.limit ?? 100) },
      timeoutMs: 15_000,
    });
    const processes = (response.data.data || []).map((proc, index) => ({
      id: proc.id || `s1-proc-${index}`,
      host: proc.agentComputerName,
      name: proc.processName || 'unknown',
      commandLine: proc.cmdLine,
      parentName: proc.parentProcessName,
      parentPid: proc.parentPid,
      pid: proc.pid,
      user: proc.user,
      startTime: proc.startTime ? Date.parse(proc.startTime) : undefined,
      raw: proc as unknown as Record<string, unknown>,
    } satisfies ProcessRecord));
    return { value: processes, provenance: provenance(this.metadata, 'searchProcesses') };
  }

  async searchNetworkConnections(query: EventSearchQuery & { host?: string; remoteAddress?: string }): Promise<IntegrationObservation<NetworkConnectionRecord[]>> {
    const filter = [
      query.host ? `agentComputerName.contains='${sanitize(query.host)}'` : null,
      query.remoteAddress ? `dstIp='${sanitize(query.remoteAddress)}'` : null,
    ].filter(Boolean).join(' AND ') || null;
    const response = await adapterFetch<SentinelOneResponse<SentinelOneConnection>>({
      url: `${this.baseUrl.replace(/\/$/, '')}/web/api/v2.1/network/connections`,
      method: 'POST',
      headers: { Authorization: `ApiToken ${this.token}` },
      body: { filter, limit: Math.max(1, query.limit ?? 100) },
      timeoutMs: 15_000,
    });
    const connections = (response.data.data || []).map((conn, index) => ({
      id: conn.id || `s1-conn-${index}`,
      host: conn.agentComputerName,
      processName: conn.processName,
      remoteAddress: conn.dstIp || '',
      remotePort: conn.dstPort,
      localAddress: conn.srcIp,
      protocol: conn.protocol,
      timestamp: conn.timestamp ? Date.parse(conn.timestamp) : undefined,
      raw: conn as unknown as Record<string, unknown>,
    } satisfies NetworkConnectionRecord));
    return { value: connections, provenance: provenance(this.metadata, 'searchNetworkConnections') };
  }

  async searchDns(query: EventSearchQuery & { host?: string; name?: string }): Promise<IntegrationObservation<DnsRecord[]>> {
    const filter = [
      query.host ? `agentComputerName.contains='${sanitize(query.host)}'` : null,
      query.name ? `domainName.contains='${sanitize(query.name)}'` : null,
    ].filter(Boolean).join(' AND ') || null;
    const response = await adapterFetch<SentinelOneResponse<SentinelOneDns>>({
      url: `${this.baseUrl.replace(/\/$/, '')}/web/api/v2.1/network/dns`,
      method: 'POST',
      headers: { Authorization: `ApiToken ${this.token}` },
      body: { filter, limit: Math.max(1, query.limit ?? 100) },
      timeoutMs: 15_000,
    });
    const records = (response.data.data || []).map((dns, index) => ({
      id: dns.id || `s1-dns-${index}`,
      host: dns.agentComputerName,
      query: dns.domainName || '',
      queryType: dns.queryType,
      response: dns.answer,
      timestamp: dns.timestamp ? Date.parse(dns.timestamp) : undefined,
      raw: dns as unknown as Record<string, unknown>,
    } satisfies DnsRecord));
    return { value: records, provenance: provenance(this.metadata, 'searchDns') };
  }
}

function sanitize(input: string): string {
  return input.replace(/['\\]/g, '').slice(0, 200);
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

export function createSentinelOneFactory(): AdapterFactory {
  return {
    domain: 'edr',
    vendor: 'sentinelone',
    adapterId: 'sentinelone-singularity',
    requiredCredentials: [
      { envVar: 'SENTINELONE_BASE_URL', configKey: 'baseUrl' },
      { envVar: 'SENTINELONE_TOKEN', configKey: 'token' },
    ],
    build(resolver: IntegrationCredentialResolver) {
      const baseUrl = resolveCredential(resolver, 'edr', 'sentinelone', 'SENTINELONE_BASE_URL', 'baseUrl').value;
      const token = resolveCredential(resolver, 'edr', 'sentinelone', 'SENTINELONE_TOKEN', 'token').value;
      return new SentinelOneEdrAdapter(baseUrl, token);
    },
  };
}
