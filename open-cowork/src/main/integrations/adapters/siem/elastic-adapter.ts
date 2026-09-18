/**
 * @module main/integrations/adapters/siem/elastic-adapter
 *
 * Elastic SIEM adapter using the _search API. Vendor-specific KQL/SPL
 * translation is contained here.
 */

import type { AdapterFactory } from '../../integration-registry';
import type { IntegrationCredentialResolver } from '../../integration-credentials';
import type { EventRecord, EventSearchQuery, IntegrationMetadata, IntegrationObservation, SiemAdapter } from '../../integration-types';
import { resolveCredential } from '../../integration-registry';
import { adapterFetch } from '../adapter-http-client';

export const ELASTIC_METADATA: IntegrationMetadata = {
  domain: 'siem',
  vendor: 'elastic',
  adapterId: 'elastic-search',
  displayName: 'Elastic Security (Search API)',
  description: 'Query Elastic indices using the _search API with KQL translated to DSL.',
  capabilities: { searchEvents: true },
};

interface ElasticSearchResponse {
  hits?: {
    hits?: Array<{
      _id?: string;
      _source?: Record<string, unknown>;
      _index?: string;
    }>;
  };
}

export class ElasticSiemAdapter implements SiemAdapter {
  readonly metadata = ELASTIC_METADATA;

  constructor(
    private readonly baseUrl: string,
    private readonly apiKey: string,
    private readonly index: string
  ) {}

  async health() {
    try {
      await adapterFetch({
        url: `${this.baseUrl.replace(/\/$/, '')}/_cluster/health`,
        method: 'GET',
        headers: { Authorization: `ApiKey ${this.apiKey}` },
        timeoutMs: 5000,
      });
      return { available: true, checkedAt: Date.now() };
    } catch (error) {
      return {
        available: false,
        reason: error instanceof Error ? error.message : 'Elastic health check failed',
        checkedAt: Date.now(),
      };
    }
  }

  async searchEvents(query: EventSearchQuery): Promise<IntegrationObservation<EventRecord[]>> {
    const body = buildElasticBody(query);
    const response = await adapterFetch<ElasticSearchResponse>({
      url: `${this.baseUrl.replace(/\/$/, '')}/${encodeURIComponent(this.index)}/_search`,
      method: 'POST',
      headers: { Authorization: `ApiKey ${this.apiKey}` },
      body,
      timeoutMs: 15_000,
    });
    const hits = response.data.hits?.hits || [];
    const records = hits.map((hit, index) => normalizeEvent(hit, index));
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

function buildElasticBody(query: EventSearchQuery): Record<string, unknown> {
  const limit = Math.max(1, query.limit ?? 100);
  const must: Array<Record<string, unknown>> = [];
  if (query.query) {
    must.push({ query_string: { query: sanitize(query.query) } });
  }
  if (query.startTime || query.endTime) {
    const range: Record<string, string> = {};
    if (query.startTime) range.gte = new Date(query.startTime).toISOString();
    if (query.endTime) range.lte = new Date(query.endTime).toISOString();
    must.push({ range: { '@timestamp': range } });
  }
  return { size: limit, query: { bool: { must } } };
}

function sanitize(input: string): string {
  return input.replace(/[\r\n]+/g, ' ').slice(0, 1000);
}

function normalizeEvent(hit: NonNullable<NonNullable<ElasticSearchResponse['hits']>['hits']>[number], index: number): EventRecord {
  const source = hit._source || {};
  const message = String(source.message || source.msg || source['@message'] || JSON.stringify(source));
  return {
    id: hit._id || `elastic-${index}`,
    timestamp: source['@timestamp'] ? Date.parse(String(source['@timestamp'])) : Date.now(),
    source: String(source.source || hit._index || 'elastic'),
    severity: source.severity as string | undefined,
    message,
    raw: source,
  };
}

export function createElasticFactory(): AdapterFactory {
  return {
    domain: 'siem',
    vendor: 'elastic',
    adapterId: 'elastic-search',
    requiredCredentials: [
      { envVar: 'ELASTIC_BASE_URL', configKey: 'baseUrl' },
      { envVar: 'ELASTIC_API_KEY', configKey: 'apiKey' },
      { envVar: 'ELASTIC_INDEX', configKey: 'index' },
    ],
    build(resolver: IntegrationCredentialResolver) {
      const baseUrl = resolveCredential(resolver, 'siem', 'elastic', 'ELASTIC_BASE_URL', 'baseUrl').value;
      const apiKey = resolveCredential(resolver, 'siem', 'elastic', 'ELASTIC_API_KEY', 'apiKey').value;
      const index = resolveCredential(resolver, 'siem', 'elastic', 'ELASTIC_INDEX', 'index').value;
      return new ElasticSiemAdapter(baseUrl, apiKey, index);
    },
  };
}
