/**
 * @module main/integrations/adapters/siem/sentinel-adapter
 *
 * Microsoft Sentinel adapter using KQL via the Log Analytics REST API.
 */

import type { AdapterFactory } from '../../integration-registry';
import type { IntegrationCredentialResolver } from '../../integration-credentials';
import type { EventRecord, EventSearchQuery, IntegrationMetadata, IntegrationObservation, SiemAdapter } from '../../integration-types';
import { resolveCredential } from '../../integration-registry';
import { adapterFetch } from '../adapter-http-client';

export const SENTINEL_METADATA: IntegrationMetadata = {
  domain: 'siem',
  vendor: 'sentinel',
  adapterId: 'sentinel-log-analytics',
  displayName: 'Microsoft Sentinel (Log Analytics)',
  description: 'Run KQL queries against Microsoft Sentinel via the Log Analytics API.',
  capabilities: { searchEvents: true },
};

interface SentinelResponse {
  tables?: Array<{
    rows?: Array<Array<string | number | boolean | null>>;
    columns?: Array<{ name: string; type: string }>;
  }>;
}

export class SentinelSiemAdapter implements SiemAdapter {
  readonly metadata = SENTINEL_METADATA;

  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
    private readonly workspaceId: string
  ) {}

  async health() {
    try {
      await adapterFetch({
        url: `${this.baseUrl.replace(/\/$/, '')}/v1/workspaces/${encodeURIComponent(this.workspaceId)}/metadata`,
        method: 'POST',
        headers: { Authorization: `Bearer ${this.token}`, 'Content-Type': 'application/json' },
        body: { query: 'print 1' },
        timeoutMs: 5000,
      });
      return { available: true, checkedAt: Date.now() };
    } catch (error) {
      return {
        available: false,
        reason: error instanceof Error ? error.message : 'Sentinel health check failed',
        checkedAt: Date.now(),
      };
    }
  }

  async searchEvents(query: EventSearchQuery): Promise<IntegrationObservation<EventRecord[]>> {
    const kql = buildKql(query);
    const response = await adapterFetch<SentinelResponse>({
      url: `${this.baseUrl.replace(/\/$/, '')}/v1/workspaces/${encodeURIComponent(this.workspaceId)}/query`,
      method: 'POST',
      headers: { Authorization: `Bearer ${this.token}`, 'Content-Type': 'application/json' },
      body: { query: kql, timespan: buildTimespan(query) },
      timeoutMs: 15_000,
    });
    const table = response.data.tables?.[0];
    const rows = table?.rows || [];
    const columns = table?.columns || [];
    const records = rows.map((row, index) => normalizeRow(columns, row, index));
    return {
      value: records,
      provenance: {
        domain: 'siem',
        adapterId: this.metadata.adapterId,
        vendor: this.metadata.vendor,
        capability: 'searchEvents',
        method: 'api_query',
        collectedAt: Date.now(),
        sourceLabel: this.workspaceId,
      },
    };
  }
}

function buildKql(query: EventSearchQuery): string {
  const limit = Math.max(1, query.limit ?? 100);
  const search = query.query ? sanitize(query.query) : '*';
  return `${search} | limit ${limit}`;
}

function buildTimespan(query: EventSearchQuery): string {
  const start = query.startTime ? new Date(query.startTime).toISOString() : new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const end = query.endTime ? new Date(query.endTime).toISOString() : new Date().toISOString();
  return `${start}/${end}`;
}

function sanitize(input: string): string {
  return input.replace(/[\r\n]+/g, ' ').slice(0, 1000);
}

function normalizeRow(columns: NonNullable<NonNullable<SentinelResponse['tables']>[number]['columns']>, row: Array<string | number | boolean | null>, index: number): EventRecord {
  const raw: Record<string, unknown> = {};
  let timestamp = Date.now();
  let message = '';
  let source = 'sentinel';
  let severity: string | undefined;
  for (let i = 0; i < columns.length; i++) {
    const column = columns[i];
    const value = row[i];
    raw[column.name] = value;
    if (/time/i.test(column.name) && value) {
      const parsed = Date.parse(String(value));
      if (!Number.isNaN(parsed)) timestamp = parsed;
    }
    if (column.name === 'Message' || column.name === 'message') message = String(value || '');
    if (column.name === 'Source' || column.name === 'source') source = String(value || source);
    if (column.name === 'Severity' || column.name === 'severity') severity = String(value || '');
  }
  return {
    id: `sentinel-${index}-${timestamp}`,
    timestamp,
    source,
    severity,
    message: message || JSON.stringify(raw),
    raw,
  };
}

export function createSentinelFactory(): AdapterFactory {
  return {
    domain: 'siem',
    vendor: 'sentinel',
    adapterId: 'sentinel-log-analytics',
    requiredCredentials: [
      { envVar: 'SENTINEL_BASE_URL', configKey: 'baseUrl' },
      { envVar: 'SENTINEL_TOKEN', configKey: 'token' },
      { envVar: 'SENTINEL_WORKSPACE_ID', configKey: 'workspaceId' },
    ],
    build(resolver: IntegrationCredentialResolver) {
      const baseUrl = resolveCredential(resolver, 'siem', 'sentinel', 'SENTINEL_BASE_URL', 'baseUrl').value;
      const token = resolveCredential(resolver, 'siem', 'sentinel', 'SENTINEL_TOKEN', 'token').value;
      const workspaceId = resolveCredential(resolver, 'siem', 'sentinel', 'SENTINEL_WORKSPACE_ID', 'workspaceId').value;
      return new SentinelSiemAdapter(baseUrl, token, workspaceId);
    },
  };
}
