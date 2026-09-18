/**
 * @module main/integrations/adapters/cloud-logs/gcp-audit-adapter
 *
 * Google Cloud Audit Logs adapter using the Logging API entries.list.
 */

import type { AdapterFactory } from '../../integration-registry';
import type { IntegrationCredentialResolver } from '../../integration-credentials';
import type { CloudLogQuery, CloudLogRecord, CloudLogsAdapter, IntegrationMetadata, IntegrationObservation } from '../../integration-types';
import { resolveCredential } from '../../integration-registry';
import { adapterFetch } from '../adapter-http-client';

export const GCP_AUDIT_METADATA: IntegrationMetadata = {
  domain: 'cloud-logs',
  vendor: 'gcp',
  adapterId: 'gcp-audit-logs',
  displayName: 'Google Cloud Audit Logs',
  description: 'Query Google Cloud audit logs via the Cloud Logging entries.list API.',
  capabilities: { queryCloudLogs: true },
};

interface GcpEntriesResponse {
  entries?: Array<{
    insertId?: string;
    timestamp?: string;
    logName?: string;
    resource?: { type?: string; labels?: Record<string, string> };
    protoPayload?: {
      '@type'?: string;
      methodName?: string;
      serviceName?: string;
      authenticationInfo?: { principalEmail?: string };
      resourceName?: string;
      requestMetadata?: { sourceIp?: string };
    };
  }>;
}

export class GcpAuditAdapter implements CloudLogsAdapter {
  readonly metadata = GCP_AUDIT_METADATA;

  constructor(
    private readonly baseUrl: string,
    private readonly token: string
  ) {}

  async health() {
    try {
      await adapterFetch({
        url: `${this.baseUrl.replace(/\/$/, '')}/v2/projects/_/locations/global`,
        method: 'GET',
        headers: { Authorization: `Bearer ${this.token}` },
        timeoutMs: 5000,
      });
      return { available: true, checkedAt: Date.now() };
    } catch (error) {
      return {
        available: false,
        reason: error instanceof Error ? error.message : 'GCP audit log health check failed',
        checkedAt: Date.now(),
      };
    }
  }

  async queryCloudLogs(query: CloudLogQuery): Promise<IntegrationObservation<CloudLogRecord[]>> {
    const filter = buildFilter(query);
    const params = new URLSearchParams();
    if (filter) params.set('filter', filter);
    params.set('pageSize', String(Math.max(1, Math.min(1000, query.limit ?? 100))));
    const url = `${this.baseUrl.replace(/\/$/, '')}/v2/entries:list?${params.toString()}`;
    const response = await adapterFetch<GcpEntriesResponse>({
      url,
      method: 'GET',
      headers: { Authorization: `Bearer ${this.token}` },
      timeoutMs: 15_000,
    });
    const records = (response.data.entries || []).map((entry, index) => normalize(entry, index));
    return { value: records, provenance: provenance(this.metadata) };
  }
}

function buildFilter(query: CloudLogQuery): string {
  const clauses: string[] = [];
  if (query.service) clauses.push(`protoPayload.serviceName="${sanitize(query.service)}"`);
  if (query.eventName) clauses.push(`protoPayload.methodName="${sanitize(query.eventName)}"`);
  if (query.startTime) clauses.push(`timestamp >= "${new Date(query.startTime).toISOString()}"`);
  if (query.endTime) clauses.push(`timestamp <= "${new Date(query.endTime).toISOString()}"`);
  return clauses.join(' AND ');
}

function sanitize(input: string): string {
  return input.replace(/["\\\r\n]/g, '').slice(0, 200);
}

function normalize(entry: NonNullable<GcpEntriesResponse['entries']>[number], index: number): CloudLogRecord {
  const proto = entry.protoPayload;
  return {
    id: entry.insertId || `gcp-${index}`,
    timestamp: entry.timestamp ? Date.parse(entry.timestamp) : Date.now(),
    service: proto?.serviceName || entry.resource?.type || 'gcp',
    eventName: proto?.methodName || 'unknown',
    actor: proto?.authenticationInfo?.principalEmail,
    resource: proto?.resourceName,
    sourceIp: proto?.requestMetadata?.sourceIp,
    raw: entry as unknown as Record<string, unknown>,
  };
}

function provenance(metadata: IntegrationMetadata) {
  return {
    domain: 'cloud-logs' as const,
    adapterId: metadata.adapterId,
    vendor: metadata.vendor,
    capability: 'queryCloudLogs',
    method: 'api_query' as const,
    collectedAt: Date.now(),
  };
}

export function createGcpAuditFactory(): AdapterFactory {
  return {
    domain: 'cloud-logs',
    vendor: 'gcp',
    adapterId: 'gcp-audit-logs',
    requiredCredentials: [
      { envVar: 'GCP_LOGGING_BASE_URL', configKey: 'baseUrl' },
      { envVar: 'GCP_TOKEN', configKey: 'token' },
    ],
    build(resolver: IntegrationCredentialResolver) {
      const baseUrl = resolveCredential(resolver, 'cloud-logs', 'gcp', 'GCP_LOGGING_BASE_URL', 'baseUrl').value;
      const token = resolveCredential(resolver, 'cloud-logs', 'gcp', 'GCP_TOKEN', 'token').value;
      return new GcpAuditAdapter(baseUrl, token);
    },
  };
}
