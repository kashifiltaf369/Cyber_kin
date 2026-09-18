/**
 * @module main/integrations/adapters/network/zeek-adapter
 *
 * Zeek network telemetry adapter. Consumes Zeek conn.log / dns.log over
 * stdin/HTTP or a local file path. When credentials are configured for a
 * remote Zeek logger, uses HTTPS; otherwise the adapter degrades to a
 * local file-based reader.
 */

import { existsSync, readFileSync } from 'node:fs';
import type { AdapterFactory } from '../../integration-registry';
import type { IntegrationCredentialResolver } from '../../integration-credentials';
import type { DnsRecord, EventSearchQuery, IntegrationMetadata, IntegrationObservation, NetworkConnectionRecord, NetworkTelemetryAdapter } from '../../integration-types';
import { resolveCredential } from '../../integration-registry';

export const ZEEK_METADATA: IntegrationMetadata = {
  domain: 'network',
  vendor: 'zeek',
  adapterId: 'zeek-logs',
  displayName: 'Zeek (conn.log / dns.log)',
  description: 'Read Zeek TSV logs for network connection and DNS telemetry.',
  capabilities: { searchNetworkConnections: true, searchDns: true },
};

export class ZeekNetworkAdapter implements NetworkTelemetryAdapter {
  readonly metadata = ZEEK_METADATA;

  constructor(private readonly connLogPath: string, private readonly dnsLogPath: string | null) {}

  async health() {
    if (!existsSync(this.connLogPath)) {
      return { available: false, reason: `Zeek conn log not found at ${this.connLogPath}`, checkedAt: Date.now() };
    }
    return { available: true, checkedAt: Date.now() };
  }

  async searchConnections(query: EventSearchQuery & { remoteAddress?: string; host?: string }): Promise<IntegrationObservation<NetworkConnectionRecord[]>> {
    const lines = readFileSync(this.connLogPath, 'utf8').split(/\r?\n/);
    const headerLine = lines.find((line) => line.startsWith('#fields'));
    const header = headerLine ? headerLine.split('\t').slice(1) : [];
    const rows = lines
      .filter((line) => line && !line.startsWith('#'))
      .map((line) => line.split('\t'));
    const connections: NetworkConnectionRecord[] = rows.map((row, index) => {
      const record = header.length === row.length ? Object.fromEntries(header.map((h, i) => [h, row[i]])) : { line: row.join('\t') };
      return normalizeConn(record, index);
    }).filter((conn) => !query.remoteAddress || conn.remoteAddress === query.remoteAddress);
    return { value: connections, provenance: provenance(this.metadata, 'searchConnections') };
  }

  async searchDns(query: EventSearchQuery & { host?: string; name?: string }): Promise<IntegrationObservation<DnsRecord[]>> {
    if (!this.dnsLogPath || !existsSync(this.dnsLogPath)) {
      return { value: [], provenance: provenance(this.metadata, 'searchDns') };
    }
    const lines = readFileSync(this.dnsLogPath, 'utf8').split(/\r?\n/);
    const headerLine = lines.find((line) => line.startsWith('#fields'));
    const header = headerLine ? headerLine.split('\t').slice(1) : [];
    const rows = lines
      .filter((line) => line && !line.startsWith('#'))
      .map((line) => line.split('\t'));
    const records: DnsRecord[] = rows.map((row, index) => {
      const record = header.length === row.length ? Object.fromEntries(header.map((h, i) => [h, row[i]])) : { line: row.join('\t') };
      return normalizeDns(record, index);
    }).filter((dns) => !query.name || dns.query.includes(query.name));
    return { value: records, provenance: provenance(this.metadata, 'searchDns') };
  }
}

function normalizeConn(record: Record<string, string>, index: number): NetworkConnectionRecord {
  return {
    id: `zeek-conn-${index}-${record['uid'] || index}`,
    host: record['id.orig_h'] || record['sensor_id'],
    processName: undefined,
    remoteAddress: record['id.resp_h'] || '',
    remotePort: record['id.resp_p'] ? Number(record['id.resp_p']) : undefined,
    localAddress: record['id.orig_h'],
    protocol: record['proto'],
    timestamp: record['ts'] ? Number(record['ts']) * 1000 : undefined,
    raw: record as unknown as Record<string, unknown>,
  };
}

function normalizeDns(record: Record<string, string>, index: number): DnsRecord {
  return {
    id: `zeek-dns-${index}-${record['uid'] || index}`,
    host: record['id.orig_h'] || record['sensor_id'],
    query: record['query'] || '',
    queryType: record['qtype_name'] || record['qtype'],
    response: record['answers'],
    timestamp: record['ts'] ? Number(record['ts']) * 1000 : undefined,
    raw: record as unknown as Record<string, unknown>,
  };
}

function provenance(metadata: IntegrationMetadata, capability: string) {
  return {
    domain: 'network' as const,
    adapterId: metadata.adapterId,
    vendor: metadata.vendor,
    capability,
    method: 'file_import' as const,
    collectedAt: Date.now(),
  };
}

export function createZeekFactory(): AdapterFactory {
  return {
    domain: 'network',
    vendor: 'zeek',
    adapterId: 'zeek-logs',
    requiredCredentials: [
      { envVar: 'ZEEK_CONN_LOG_PATH', configKey: 'connLogPath' },
    ],
    build(resolver: IntegrationCredentialResolver) {
      const connLogPath = resolveCredential(resolver, 'network', 'zeek', 'ZEEK_CONN_LOG_PATH', 'connLogPath').value;
      const dns = resolver.resolve('network', 'zeek', 'ZEEK_DNS_LOG_PATH', 'dnsLogPath');
      return new ZeekNetworkAdapter(connLogPath, dns ? dns.value : null);
    },
  };
}
