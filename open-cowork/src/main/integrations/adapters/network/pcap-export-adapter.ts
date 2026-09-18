/**
 * @module main/integrations/adapters/network/pcap-export-adapter
 *
 * Adapter that reads network telemetry from a vendor-exported CSV/JSON
 * snapshot file. No network calls; vendor-specific parsing happens here.
 */

import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { AdapterFactory } from '../../integration-registry';
import type { IntegrationCredentialResolver } from '../../integration-credentials';
import type { DnsRecord, EventSearchQuery, IntegrationMetadata, IntegrationObservation, NetworkConnectionRecord, NetworkTelemetryAdapter } from '../../integration-types';
import { resolveCredential } from '../../integration-registry';

export const PCAP_EXPORT_METADATA: IntegrationMetadata = {
  domain: 'network',
  vendor: 'pcap-export',
  adapterId: 'pcap-export-snapshot',
  displayName: 'PCAP text export',
  description: 'Parse vendor-exported network connection and DNS snapshots (CSV/JSON).',
  capabilities: { searchNetworkConnections: true, searchDns: true },
};

export class PcapExportNetworkAdapter implements NetworkTelemetryAdapter {
  readonly metadata = PCAP_EXPORT_METADATA;

  constructor(private readonly exportPath: string) {}

  async health() {
    if (!existsSync(this.exportPath)) {
      return { available: false, reason: `Export file not found at ${this.exportPath}`, checkedAt: Date.now() };
    }
    return { available: true, checkedAt: Date.now() };
  }

  async searchConnections(query: EventSearchQuery & { remoteAddress?: string; host?: string }): Promise<IntegrationObservation<NetworkConnectionRecord[]>> {
    const records = parseStructuredFile(this.exportPath, ['connections', 'items', 'records']);
    const connections = records
      .map((record, index) => ({
        id: `pcap-conn-${index}`,
        host: record.host as string | undefined,
        processName: record.processName as string | undefined,
        remoteAddress: String(record.remoteAddress || record.dstIp || ''),
        remotePort: record.remotePort as number | undefined,
        localAddress: record.localAddress as string | undefined,
        protocol: record.protocol as string | undefined,
        timestamp: record.timestamp ? Number(record.timestamp) : undefined,
        raw: record,
      } satisfies NetworkConnectionRecord))
      .filter((conn) => !query.remoteAddress || conn.remoteAddress === query.remoteAddress);
    return { value: connections, provenance: provenance(this.metadata, 'searchConnections') };
  }

  async searchDns(query: EventSearchQuery & { host?: string; name?: string }): Promise<IntegrationObservation<DnsRecord[]>> {
    const records = parseStructuredFile(this.exportPath, ['dns', 'items', 'records']);
    const dns = records
      .map((record, index) => ({
        id: `pcap-dns-${index}`,
        host: record.host as string | undefined,
        query: String(record.query || record.domain || ''),
        queryType: record.queryType as string | undefined,
        response: record.response as string | undefined,
        timestamp: record.timestamp ? Number(record.timestamp) : undefined,
        raw: record,
      } satisfies DnsRecord))
      .filter((entry) => !query.name || entry.query.includes(query.name));
    return { value: dns, provenance: provenance(this.metadata, 'searchDns') };
  }
}

function parseStructuredFile(filePath: string, arrayKeys: string[]): Array<Record<string, unknown>> {
  if (!existsSync(filePath)) return [];
  const ext = path.extname(filePath).toLowerCase();
  const content = readFileSync(filePath, 'utf8');
  if (ext === '.json') {
    try {
      const parsed: unknown = JSON.parse(content);
      if (Array.isArray(parsed)) return parsed.filter(isRecord);
      if (isRecord(parsed)) {
        for (const key of arrayKeys) {
          const value = parsed[key];
          if (Array.isArray(value)) return value.filter(isRecord);
        }
        return [parsed];
      }
    } catch {
      return [];
    }
  }
  if (ext === '.csv') {
    const lines = content.split(/\r?\n/).filter(Boolean);
    if (lines.length === 0) return [];
    const headers = lines[0].split(',').map((h) => h.trim());
    return lines.slice(1).map((line) => {
      const values = line.split(',');
      return headers.reduce<Record<string, unknown>>((acc, header, index) => {
        acc[header] = (values[index] || '').trim();
        return acc;
      }, {});
    });
  }
  return [];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
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

export function createPcapExportFactory(): AdapterFactory {
  return {
    domain: 'network',
    vendor: 'pcap-export',
    adapterId: 'pcap-export-snapshot',
    requiredCredentials: [{ envVar: 'NETWORK_EXPORT_PATH', configKey: 'exportPath' }],
    build(resolver: IntegrationCredentialResolver) {
      const exportPath = resolveCredential(resolver, 'network', 'pcap-export', 'NETWORK_EXPORT_PATH', 'exportPath').value;
      return new PcapExportNetworkAdapter(exportPath);
    },
  };
}
