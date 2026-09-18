/**
 * @module main/integrations/adapters/edr/defender-adapter
 *
 * Microsoft Defender for Endpoint adapter (MDE) using the Advanced Hunting API.
 */

import type { AdapterFactory } from '../../integration-registry';
import type { IntegrationCredentialResolver } from '../../integration-credentials';
import type { DnsRecord, EdrAdapter, EventSearchQuery, IntegrationMetadata, IntegrationObservation, NetworkConnectionRecord, ProcessRecord } from '../../integration-types';
import { resolveCredential } from '../../integration-registry';
import { adapterFetch } from '../adapter-http-client';

export const DEFENDER_METADATA: IntegrationMetadata = {
  domain: 'edr',
  vendor: 'defender',
  adapterId: 'defender-mde',
  displayName: 'Microsoft Defender for Endpoint',
  description: 'Advanced Hunting queries (ProcessCreationEvents, DeviceNetworkEvents, DeviceEvents).',
  capabilities: { searchProcesses: true, searchNetworkConnections: true, searchDns: true },
};

interface DefenderResponse {
  Results?: Array<Record<string, unknown>>;
}

export class DefenderEdrAdapter implements EdrAdapter {
  readonly metadata = DEFENDER_METADATA;

  constructor(
    private readonly baseUrl: string,
    private readonly token: string
  ) {}

  async health() {
    try {
      await adapterFetch({
        url: `${this.baseUrl.replace(/\/$/, '')}/api/machines`,
        method: 'GET',
        headers: { Authorization: `Bearer ${this.token}` },
        timeoutMs: 5000,
      });
      return { available: true, checkedAt: Date.now() };
    } catch (error) {
      return {
        available: false,
        reason: error instanceof Error ? error.message : 'Defender health check failed',
        checkedAt: Date.now(),
      };
    }
  }

  async searchProcesses(query: EventSearchQuery & { host?: string; name?: string }): Promise<IntegrationObservation<ProcessRecord[]>> {
    const kql = buildKql('ProcessCreationEvents', query, [
      ['DeviceName', query.host],
      ['FileName', query.name],
      ['ProcessCommandLine', query.query],
    ]);
    return this.runProcessQuery(kql);
  }

  async searchNetworkConnections(query: EventSearchQuery & { host?: string; remoteAddress?: string }): Promise<IntegrationObservation<NetworkConnectionRecord[]>> {
    const kql = buildKql('DeviceNetworkEvents', query, [
      ['DeviceName', query.host],
      ['RemoteIP', query.remoteAddress],
    ]);
    return this.runConnectionQuery(kql);
  }

  async searchDns(query: EventSearchQuery & { host?: string; name?: string }): Promise<IntegrationObservation<DnsRecord[]>> {
    const kql = buildKql('DeviceEvents', query, [
      ['DeviceName', query.host],
      ['RemoteUrl', query.name],
    ], "ActionType == 'DnsQuery'");
    return this.runDnsQuery(kql);
  }

  private async runProcessQuery(kql: string): Promise<IntegrationObservation<ProcessRecord[]>> {
    const response = await adapterFetch<DefenderResponse>({
      url: `${this.baseUrl.replace(/\/$/, '')}/api/advancedhunting/run`,
      method: 'POST',
      headers: { Authorization: `Bearer ${this.token}`, 'Content-Type': 'application/json' },
      body: { Query: kql },
      timeoutMs: 15_000,
    });
    const processes = (response.data.Results || []).map((row, index) => ({
      id: String(row.ReportId || `mde-proc-${index}`),
      host: row.DeviceName as string | undefined,
      name: (row.FileName as string) || 'unknown',
      commandLine: row.ProcessCommandLine as string | undefined,
      parentName: row.InitiatingProcessFileName as string | undefined,
      parentPid: row.InitiatingProcessParentId as number | undefined,
      pid: row.ProcessId as number | undefined,
      user: row.AccountName as string | undefined,
      startTime: row.Timestamp ? Date.parse(String(row.Timestamp)) : undefined,
      raw: row,
    } satisfies ProcessRecord));
    return { value: processes, provenance: provenance(this.metadata, 'searchProcesses') };
  }

  private async runConnectionQuery(kql: string): Promise<IntegrationObservation<NetworkConnectionRecord[]>> {
    const response = await adapterFetch<DefenderResponse>({
      url: `${this.baseUrl.replace(/\/$/, '')}/api/advancedhunting/run`,
      method: 'POST',
      headers: { Authorization: `Bearer ${this.token}`, 'Content-Type': 'application/json' },
      body: { Query: kql },
      timeoutMs: 15_000,
    });
    const connections = (response.data.Results || []).map((row, index) => ({
      id: String(row.ReportId || `mde-conn-${index}`),
      host: row.DeviceName as string | undefined,
      processName: row.InitiatingProcessFileName as string | undefined,
      remoteAddress: String(row.RemoteIP || ''),
      remotePort: row.RemotePort as number | undefined,
      localAddress: row.LocalIP as string | undefined,
      protocol: row.Protocol as string | undefined,
      timestamp: row.Timestamp ? Date.parse(String(row.Timestamp)) : undefined,
      raw: row,
    } satisfies NetworkConnectionRecord));
    return { value: connections, provenance: provenance(this.metadata, 'searchNetworkConnections') };
  }

  private async runDnsQuery(kql: string): Promise<IntegrationObservation<DnsRecord[]>> {
    const response = await adapterFetch<DefenderResponse>({
      url: `${this.baseUrl.replace(/\/$/, '')}/api/advancedhunting/run`,
      method: 'POST',
      headers: { Authorization: `Bearer ${this.token}`, 'Content-Type': 'application/json' },
      body: { Query: kql },
      timeoutMs: 15_000,
    });
    const records = (response.data.Results || []).map((row, index) => ({
      id: String(row.ReportId || `mde-dns-${index}`),
      host: row.DeviceName as string | undefined,
      query: String(row.RemoteUrl || ''),
      queryType: row.AdditionalFields ? String((row.AdditionalFields as Record<string, unknown>)['DNSQueryType'] || '') || undefined : undefined,
      response: row.AdditionalFields ? String((row.AdditionalFields as Record<string, unknown>)['DNSResponseName'] || '') || undefined : undefined,
      timestamp: row.Timestamp ? Date.parse(String(row.Timestamp)) : undefined,
      raw: row,
    } satisfies DnsRecord));
    return { value: records, provenance: provenance(this.metadata, 'searchDns') };
  }
}

function buildKql(
  table: string,
  query: EventSearchQuery,
  conditions: Array<[string, string | undefined]>,
  extraPredicate?: string
): string {
  const clauses = conditions
    .filter(([, value]) => value && value.length > 0)
    .map(([column, value]) => `${column} =~ '${sanitize(value || '')}'`);
  if (extraPredicate) clauses.push(extraPredicate);
  const limit = Math.max(1, query.limit ?? 100);
  return `${table} | where ${clauses.join(' and ') || 'true'} | limit ${limit}`;
}

function sanitize(input: string): string {
  return input.replace(/['\\\r\n]/g, '').slice(0, 200);
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

export function createDefenderFactory(): AdapterFactory {
  return {
    domain: 'edr',
    vendor: 'defender',
    adapterId: 'defender-mde',
    requiredCredentials: [
      { envVar: 'DEFENDER_BASE_URL', configKey: 'baseUrl' },
      { envVar: 'DEFENDER_TOKEN', configKey: 'token' },
    ],
    build(resolver: IntegrationCredentialResolver) {
      const baseUrl = resolveCredential(resolver, 'edr', 'defender', 'DEFENDER_BASE_URL', 'baseUrl').value;
      const token = resolveCredential(resolver, 'edr', 'defender', 'DEFENDER_TOKEN', 'token').value;
      return new DefenderEdrAdapter(baseUrl, token);
    },
  };
}
