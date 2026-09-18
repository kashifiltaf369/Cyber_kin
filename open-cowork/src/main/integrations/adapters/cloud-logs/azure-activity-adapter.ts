/**
 * @module main/integrations/adapters/cloud-logs/azure-activity-adapter
 *
 * Azure Activity Log adapter (subscription-level read-only).
 */

import type { AdapterFactory } from '../../integration-registry';
import type { IntegrationCredentialResolver } from '../../integration-credentials';
import type { CloudLogQuery, CloudLogRecord, CloudLogsAdapter, IntegrationMetadata, IntegrationObservation } from '../../integration-types';
import { resolveCredential } from '../../integration-registry';
import { adapterFetch } from '../adapter-http-client';

export const AZURE_ACTIVITY_METADATA: IntegrationMetadata = {
  domain: 'cloud-logs',
  vendor: 'azure',
  adapterId: 'azure-activity-log',
  displayName: 'Azure Activity Log',
  description: 'Read subscription-level Azure Activity Log entries.',
  capabilities: { queryCloudLogs: true },
};

interface AzureActivityResponse {
  value?: Array<{
    id?: string;
    timestamp?: string;
    operationName?: string;
    resourceProvider?: string;
    caller?: string;
    resourceId?: string;
    httpRequest?: { clientIpAddress?: string };
  }>;
}

export class AzureActivityAdapter implements CloudLogsAdapter {
  readonly metadata = AZURE_ACTIVITY_METADATA;

  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
    private readonly subscriptionId: string
  ) {}

  async health() {
    try {
      await adapterFetch({
        url: `${this.baseUrl.replace(/\/$/, '')}/subscriptions/${encodeURIComponent(this.subscriptionId)}/providers/microsoft.insights/eventtypes/management/values?api-version=2015-04-01&$top=1`,
        method: 'GET',
        headers: { Authorization: `Bearer ${this.token}` },
        timeoutMs: 5000,
      });
      return { available: true, checkedAt: Date.now() };
    } catch (error) {
      return {
        available: false,
        reason: error instanceof Error ? error.message : 'Azure Activity log health check failed',
        checkedAt: Date.now(),
      };
    }
  }

  async queryCloudLogs(query: CloudLogQuery): Promise<IntegrationObservation<CloudLogRecord[]>> {
    const params = new URLSearchParams();
    params.set('api-version', '2015-04-01');
    if (query.startTime) params.set('$filter', `eventTimestamp ge '${new Date(query.startTime).toISOString()}'`);
    if (query.endTime) {
      const current = params.get('$filter');
      params.set('$filter', `${current ? `${current} and ` : ''}eventTimestamp le '${new Date(query.endTime).toISOString()}'`);
    }
    const response = await adapterFetch<AzureActivityResponse>({
      url: `${this.baseUrl.replace(/\/$/, '')}/subscriptions/${encodeURIComponent(this.subscriptionId)}/providers/microsoft.insights/eventtypes/management/values?${params.toString()}`,
      method: 'GET',
      headers: { Authorization: `Bearer ${this.token}` },
      timeoutMs: 15_000,
    });
    const records = (response.data.value || []).map((entry, index) => normalize(entry, index));
    return { value: records, provenance: provenance(this.metadata) };
  }
}

function normalize(entry: NonNullable<AzureActivityResponse['value']>[number], index: number): CloudLogRecord {
  return {
    id: entry.id || `azure-${index}`,
    timestamp: entry.timestamp ? Date.parse(entry.timestamp) : Date.now(),
    service: entry.resourceProvider || 'azure',
    eventName: entry.operationName || 'unknown',
    actor: entry.caller,
    resource: entry.resourceId,
    sourceIp: entry.httpRequest?.clientIpAddress,
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

export function createAzureActivityFactory(): AdapterFactory {
  return {
    domain: 'cloud-logs',
    vendor: 'azure',
    adapterId: 'azure-activity-log',
    requiredCredentials: [
      { envVar: 'AZURE_BASE_URL', configKey: 'baseUrl' },
      { envVar: 'AZURE_TOKEN', configKey: 'token' },
      { envVar: 'AZURE_SUBSCRIPTION_ID', configKey: 'subscriptionId' },
    ],
    build(resolver: IntegrationCredentialResolver) {
      const baseUrl = resolveCredential(resolver, 'cloud-logs', 'azure', 'AZURE_BASE_URL', 'baseUrl').value;
      const token = resolveCredential(resolver, 'cloud-logs', 'azure', 'AZURE_TOKEN', 'token').value;
      const subscriptionId = resolveCredential(resolver, 'cloud-logs', 'azure', 'AZURE_SUBSCRIPTION_ID', 'subscriptionId').value;
      return new AzureActivityAdapter(baseUrl, token, subscriptionId);
    },
  };
}
