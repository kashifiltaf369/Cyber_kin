/**
 * @module main/integrations/adapters/siem/splunk-adapter
 *
 * Splunk SIEM adapter. Vendor-specific REST details live here; the
 * investigation engine only ever sees the vendor-neutral `SiemAdapter`.
 */

import type { AdapterFactory } from '../../integration-registry';
import type { IntegrationCredentialResolver } from '../../integration-credentials';
import type { EventRecord, EventSearchQuery, IntegrationMetadata, IntegrationObservation, SiemAdapter } from '../../integration-types';
import { resolveCredential } from '../../integration-registry';
import { adapterFetch } from '../adapter-http-client';

export const SPLUNK_METADATA: IntegrationMetadata = {
  domain: 'siem',
  vendor: 'splunk',
  adapterId: 'splunk-rest',
  displayName: 'Splunk (REST)',
  description: 'Search Splunk indexes via the Splunk REST API.',
  capabilities: { searchEvents: true },
};

interface SplunkSearchResponse {
  results?: Array<{
    _time?: string;
    _raw?: string;
    source?: string;
    sourcetype?: string;
    index?: string;
    severity?: string;
  }>;
}

export class SplunkSiemAdapter implements SiemAdapter {
  readonly metadata = SPLUNK_METADATA;

  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
    private readonly index: string
  ) {}

  async health() {
    try {
      await adapterFetch({
        url: `${this.baseUrl.replace(/\/$/, '')}/services/authentication/httpauth-tokens`,
        method: 'GET',
        headers: { Authorization: `Bearer ${this.token}` },
        timeoutMs: 5000,
      });
      return { available: true, checkedAt: Date.now() };
    } catch (error) {
      return {
        available: false,
        reason: error instanceof Error ? error.message : 'Splunk health check failed',
        checkedAt: Date.now(),
      };
    }
  }

  async searchEvents(query: EventSearchQuery): Promise<IntegrationObservation<EventRecord[]>> {
    const spl = buildSplQuery(query, this.index);
    const response = await adapterFetch<SplunkSearchResponse>({
      url: `${this.baseUrl.replace(/\/$/, '')}/services/search/jobs/export`,
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.token}`,
      },
      body: { search: spl, output_mode: 'json', count: query.limit ?? 100 },
      timeoutMs: 15_000,
    });
    const records = (response.data.results || []).map((result, index) => normalizeEvent(result, index));
    return {
      value: records,
      provenance: {
        domain: 'siem',
        adapterId: this.metadata.adapterId,
        vendor: this.metadata.vendor,
        capability: 'searchEvents',
        method: 'api_query',
        collectedAt: Date.now(),
        sourceLabel: this.index,
      },
    };
  }
}

function buildSplQuery(query: EventSearchQuery, index: string): string {
  const limit = Math.max(1, query.limit ?? 100);
  const earliest = query.startTime ? `earliest=${Math.floor(query.startTime / 1000)}` : 'earliest=-24h';
  const latest = query.endTime ? `latest=${Math.floor(query.endTime / 1000)}` : 'latest=now';
  const search = query.query ? `search ${sanitize(query.query)}` : 'search *';
  return `| ${earliest} ${latest} index=${index} ${search} | head ${limit}`;
}

function sanitize(input: string): string {
  return input.replace(/[\r\n]+/g, ' ').slice(0, 1000);
}

function normalizeEvent(result: NonNullable<SplunkSearchResponse['results']>[number], index: number): EventRecord {
  const raw = result as NonNullable<SplunkSearchResponse['results']>[number];
  return {
    id: `splunk-${index}-${raw._time || Date.now()}`,
    timestamp: raw._time ? Date.parse(raw._time) : Date.now(),
    source: raw.source || raw.sourcetype || 'splunk',
    severity: raw.severity,
    message: raw._raw || '',
    raw: raw as Record<string, unknown>,
  };
}

export function createSplunkFactory(): AdapterFactory {
  return {
    domain: 'siem',
    vendor: 'splunk',
    adapterId: 'splunk-rest',
    requiredCredentials: [
      { envVar: 'SPLUNK_BASE_URL', configKey: 'baseUrl' },
      { envVar: 'SPLUNK_TOKEN', configKey: 'token' },
      { envVar: 'SPLUNK_INDEX', configKey: 'index' },
    ],
    build(resolver: IntegrationCredentialResolver) {
      const baseUrl = resolveCredential(resolver, 'siem', 'splunk', 'SPLUNK_BASE_URL', 'baseUrl').value;
      const token = resolveCredential(resolver, 'siem', 'splunk', 'SPLUNK_TOKEN', 'token').value;
      const index = resolveCredential(resolver, 'siem', 'splunk', 'SPLUNK_INDEX', 'index').value;
      return new SplunkSiemAdapter(baseUrl, token, index);
    },
  };
}
