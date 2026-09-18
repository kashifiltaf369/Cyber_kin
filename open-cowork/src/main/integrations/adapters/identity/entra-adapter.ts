/**
 * @module main/integrations/adapters/identity/entra-adapter
 *
 * Microsoft Entra ID (Azure AD) sign-in / audit log adapter.
 */

import type { AdapterFactory } from '../../integration-registry';
import type { IntegrationCredentialResolver } from '../../integration-credentials';
import type { EventSearchQuery, IdentityActivityRecord, IdentityAdapter, IntegrationMetadata, IntegrationObservation } from '../../integration-types';
import { resolveCredential } from '../../integration-registry';
import { adapterFetch } from '../adapter-http-client';

export const ENTRA_METADATA: IntegrationMetadata = {
  domain: 'identity',
  vendor: 'entra',
  adapterId: 'entra-signin-logs',
  displayName: 'Microsoft Entra ID (Sign-in Logs)',
  description: 'Query Entra ID sign-in and audit logs through the Microsoft Graph API.',
  capabilities: { searchIdentityActivity: true },
};

interface GraphResponse<T> {
  value?: T[];
  '@odata.nextLink'?: string;
}

interface GraphSignIn {
  id?: string;
  createdDateTime?: string;
  userPrincipalName?: string;
  appDisplayName?: string;
  resourceDisplayName?: string;
  ipAddress?: string;
  status?: { errorCode?: number; failureReason?: string };
  riskDetail?: string;
  riskLevelDuringSignIn?: string;
}

export class EntraIdentityAdapter implements IdentityAdapter {
  readonly metadata = ENTRA_METADATA;

  constructor(
    private readonly baseUrl: string,
    private readonly token: string
  ) {}

  async health() {
    try {
      await adapterFetch({
        url: `${this.baseUrl.replace(/\/$/, '')}/v1.0/organization`,
        method: 'GET',
        headers: { Authorization: `Bearer ${this.token}` },
        timeoutMs: 5000,
      });
      return { available: true, checkedAt: Date.now() };
    } catch (error) {
      return {
        available: false,
        reason: error instanceof Error ? error.message : 'Entra health check failed',
        checkedAt: Date.now(),
      };
    }
  }

  async queryIdentityActivity(query: EventSearchQuery & { actor?: string; action?: string }): Promise<IntegrationObservation<IdentityActivityRecord[]>> {
    const filter = buildFilter(query);
    const top = Math.max(1, query.limit ?? 100);
    const params = new URLSearchParams();
    params.set('$top', String(top));
    if (filter) params.set('$filter', filter);
    const url = `${this.baseUrl.replace(/\/$/, '')}/v1.0/auditLogs/signIns?${params.toString()}`;
    const response = await adapterFetch<GraphResponse<GraphSignIn>>({
      url,
      method: 'GET',
      headers: { Authorization: `Bearer ${this.token}` },
      timeoutMs: 15_000,
    });
    const records = (response.data.value || []).map((signin, index) => normalize(signin, index));
    return { value: records, provenance: provenance(this.metadata) };
  }
}

function buildFilter(query: EventSearchQuery & { actor?: string; action?: string }): string | null {
  const clauses: string[] = [];
  if (query.actor) clauses.push(`userPrincipalName eq '${sanitize(query.actor)}'`);
  if (query.action) clauses.push(`appDisplayName eq '${sanitize(query.action)}'`);
  if (query.startTime) clauses.push(`createdDateTime ge ${new Date(query.startTime).toISOString()}`);
  if (query.endTime) clauses.push(`createdDateTime le ${new Date(query.endTime).toISOString()}`);
  return clauses.length === 0 ? null : clauses.join(' and ');
}

function sanitize(input: string): string {
  return input.replace(/['\\]/g, '').slice(0, 200);
}

function normalize(signin: GraphSignIn, index: number): IdentityActivityRecord {
  const status = signin.status?.errorCode === 0 ? 'success' : signin.status?.errorCode ? 'failure' : 'unknown';
  return {
    id: signin.id || `entra-${index}`,
    actor: signin.userPrincipalName || 'unknown',
    action: 'sign-in',
    target: signin.resourceDisplayName || signin.appDisplayName,
    timestamp: signin.createdDateTime ? Date.parse(signin.createdDateTime) : Date.now(),
    source: 'entra-signin',
    ipAddress: signin.ipAddress,
    result: status,
    raw: signin as unknown as Record<string, unknown>,
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

export function createEntraFactory(): AdapterFactory {
  return {
    domain: 'identity',
    vendor: 'entra',
    adapterId: 'entra-signin-logs',
    requiredCredentials: [
      { envVar: 'GRAPH_BASE_URL', configKey: 'baseUrl' },
      { envVar: 'GRAPH_TOKEN', configKey: 'token' },
    ],
    build(resolver: IntegrationCredentialResolver) {
      const baseUrl = resolveCredential(resolver, 'identity', 'entra', 'GRAPH_BASE_URL', 'baseUrl').value;
      const token = resolveCredential(resolver, 'identity', 'entra', 'GRAPH_TOKEN', 'token').value;
      return new EntraIdentityAdapter(baseUrl, token);
    },
  };
}
