/**
 * @module main/integrations/adapters/identity/okta-adapter
 *
 * Okta System Log adapter.
 */

import type { AdapterFactory } from '../../integration-registry';
import type { IntegrationCredentialResolver } from '../../integration-credentials';
import type { EventSearchQuery, IdentityActivityRecord, IdentityAdapter, IntegrationMetadata, IntegrationObservation } from '../../integration-types';
import { resolveCredential } from '../../integration-registry';
import { adapterFetch } from '../adapter-http-client';

export const OKTA_METADATA: IntegrationMetadata = {
  domain: 'identity',
  vendor: 'okta',
  adapterId: 'okta-system-log',
  displayName: 'Okta System Log',
  description: 'Query Okta System Log events for authentication and account activity.',
  capabilities: { searchIdentityActivity: true },
};

interface OktaResponse {
  data?: Array<{
    uuid?: string;
    published?: string;
    actor?: { id?: string; type?: string; alternateId?: string; displayName?: string };
    eventType?: string;
    outcome?: { result?: string; reason?: string };
    client?: { ipAddress?: string };
    target?: Array<{ id?: string; type?: string; alternateId?: string; displayName?: string }>;
    debugContext?: { debugData?: Record<string, unknown> };
  }>;
}

export class OktaIdentityAdapter implements IdentityAdapter {
  readonly metadata = OKTA_METADATA;

  constructor(
    private readonly baseUrl: string,
    private readonly token: string
  ) {}

  async health() {
    try {
      await adapterFetch({
        url: `${this.baseUrl.replace(/\/$/, '')}/api/v1/users?limit=1`,
        method: 'GET',
        headers: { Authorization: `SSWS ${this.token}` },
        timeoutMs: 5000,
      });
      return { available: true, checkedAt: Date.now() };
    } catch (error) {
      return {
        available: false,
        reason: error instanceof Error ? error.message : 'Okta health check failed',
        checkedAt: Date.now(),
      };
    }
  }

  async queryIdentityActivity(query: EventSearchQuery & { actor?: string; action?: string }): Promise<IntegrationObservation<IdentityActivityRecord[]>> {
    const url = new URL(`${this.baseUrl.replace(/\/$/, '')}/api/v1/logs`);
    url.searchParams.set('limit', String(Math.max(1, query.limit ?? 100)));
    if (query.actor) url.searchParams.set('filter', `actor.id eq "${sanitize(query.actor)}"`);
    if (query.action) url.searchParams.set('filter', `eventType eq "${sanitize(query.action)}"`);
    if (query.startTime) url.searchParams.set('since', new Date(query.startTime).toISOString());
    if (query.endTime) url.searchParams.set('until', new Date(query.endTime).toISOString());
    const response = await adapterFetch<OktaResponse>({
      url: url.toString(),
      method: 'GET',
      headers: { Authorization: `SSWS ${this.token}` },
      timeoutMs: 15_000,
    });
    const records = (response.data.data || []).map((event, index) => normalize(event, index));
    return { value: records, provenance: provenance(this.metadata) };
  }
}

function sanitize(input: string): string {
  return input.replace(/['"\\]/g, '').slice(0, 200);
}

function normalize(event: NonNullable<OktaResponse['data']>[number], index: number): IdentityActivityRecord {
  return {
    id: event.uuid || `okta-${index}`,
    actor: event.actor?.alternateId || event.actor?.displayName || 'unknown',
    action: event.eventType || 'unknown',
    target: event.target?.[0]?.alternateId || event.target?.[0]?.displayName,
    timestamp: event.published ? Date.parse(event.published) : Date.now(),
    source: 'okta-system-log',
    ipAddress: event.client?.ipAddress,
    result: event.outcome?.result === 'SUCCESS' ? 'success' : event.outcome?.result === 'FAILURE' ? 'failure' : 'unknown',
    raw: event as unknown as Record<string, unknown>,
  };
}

function provenance(metadata: IntegrationMetadata) {
  return {
    domain: 'identity' as const,
    adapterId: metadata.adapterId,
    vendor: metadata.vendor,
    capability: 'queryIdentityActivity',
    method: 'api_query' as const,
    collectedAt: Date.now(),
  };
}

export function createOktaFactory(): AdapterFactory {
  return {
    domain: 'identity',
    vendor: 'okta',
    adapterId: 'okta-system-log',
    requiredCredentials: [
      { envVar: 'OKTA_BASE_URL', configKey: 'baseUrl' },
      { envVar: 'OKTA_TOKEN', configKey: 'token' },
    ],
    build(resolver: IntegrationCredentialResolver) {
      const baseUrl = resolveCredential(resolver, 'identity', 'okta', 'OKTA_BASE_URL', 'baseUrl').value;
      const token = resolveCredential(resolver, 'identity', 'okta', 'OKTA_TOKEN', 'token').value;
      return new OktaIdentityAdapter(baseUrl, token);
    },
  };
}
