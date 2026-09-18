/**
 * @module main/integrations/adapters/cloud-logs/cloudtrail-adapter
 *
 * AWS CloudTrail adapter using the LookupEvents API.
 */

import type { AdapterFactory } from '../../integration-registry';
import type { IntegrationCredentialResolver } from '../../integration-credentials';
import type { CloudLogQuery, CloudLogRecord, CloudLogsAdapter, IntegrationMetadata, IntegrationObservation } from '../../integration-types';
import { resolveCredential } from '../../integration-registry';
import { adapterFetch } from '../adapter-http-client';

export const CLOUDTRAIL_METADATA: IntegrationMetadata = {
  domain: 'cloud-logs',
  vendor: 'aws',
  adapterId: 'aws-cloudtrail',
  displayName: 'AWS CloudTrail',
  description: 'Query AWS CloudTrail events via the CloudTrail LookupEvents API.',
  capabilities: { queryCloudLogs: true },
};

interface CloudTrailResponse {
  Events?: Array<{
    EventId?: string;
    EventTime?: string;
    EventName?: string;
    EventSource?: string;
    Username?: string;
    ResourceName?: string;
    SourceIPAddress?: string;
    CloudTrailEvent?: string;
  }>;
}

export class CloudTrailAdapter implements CloudLogsAdapter {
  readonly metadata = CLOUDTRAIL_METADATA;

  constructor(
    private readonly baseUrl: string,
    private readonly accessKeyId: string,
    private readonly secretAccessKey: string,
    private readonly sessionToken?: string
  ) {}

  async health() {
    try {
      await adapterFetch({
        url: `${this.baseUrl.replace(/\/$/, '')}/`,
        method: 'POST',
        headers: this.headers(),
        body: { Action: 'DescribeTrails' },
        timeoutMs: 5000,
      });
      return { available: true, checkedAt: Date.now() };
    } catch (error) {
      return {
        available: false,
        reason: error instanceof Error ? error.message : 'CloudTrail health check failed',
        checkedAt: Date.now(),
      };
    }
  }

  async queryCloudLogs(query: CloudLogQuery): Promise<IntegrationObservation<CloudLogRecord[]>> {
    const body: Record<string, unknown> = {
      Action: 'LookupEvents',
      MaxResults: String(Math.max(1, Math.min(50, query.limit ?? 50))),
    };
    if (query.startTime) body.StartTime = new Date(query.startTime).toISOString();
    if (query.endTime) body.EndTime = new Date(query.endTime).toISOString();
    if (query.eventName) body.LookupAttributes = [{ AttributeKey: 'EventName', AttributeValue: query.eventName }];
    const response = await adapterFetch<CloudTrailResponse>({
      url: `${this.baseUrl.replace(/\/$/, '')}/`,
      method: 'POST',
      headers: this.headers(),
      body,
      timeoutMs: 15_000,
    });
    const records = (response.data.Events || []).map((event, index) => normalize(event, index));
    return { value: records, provenance: provenance(this.metadata) };
  }

  private headers(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
      'X-Amz-Access-Key-Id': this.accessKeyId,
    };
    if (this.sessionToken) headers['X-Amz-Security-Token'] = this.sessionToken;
    headers['X-Amz-Secret-Access-Key'] = this.secretAccessKey;
    return headers;
  }
}

function normalize(event: NonNullable<CloudTrailResponse['Events']>[number], index: number): CloudLogRecord {
  return {
    id: event.EventId || `cloudtrail-${index}`,
    timestamp: event.EventTime ? Date.parse(event.EventTime) : Date.now(),
    service: event.EventSource || 'cloudtrail',
    eventName: event.EventName || 'unknown',
    actor: event.Username,
    resource: event.ResourceName,
    sourceIp: event.SourceIPAddress,
    raw: event as unknown as Record<string, unknown>,
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

export function createCloudTrailFactory(): AdapterFactory {
  return {
    domain: 'cloud-logs',
    vendor: 'aws',
    adapterId: 'aws-cloudtrail',
    requiredCredentials: [
      { envVar: 'AWS_CLOUDTRAIL_BASE_URL', configKey: 'baseUrl' },
      { envVar: 'AWS_ACCESS_KEY_ID', configKey: 'accessKeyId' },
      { envVar: 'AWS_SECRET_ACCESS_KEY', configKey: 'secretAccessKey' },
    ],
    build(resolver: IntegrationCredentialResolver) {
      const baseUrl = resolveCredential(resolver, 'cloud-logs', 'aws', 'AWS_CLOUDTRAIL_BASE_URL', 'baseUrl').value;
      const accessKeyId = resolveCredential(resolver, 'cloud-logs', 'aws', 'AWS_ACCESS_KEY_ID', 'accessKeyId').value;
      const secretAccessKey = resolveCredential(resolver, 'cloud-logs', 'aws', 'AWS_SECRET_ACCESS_KEY', 'secretAccessKey').value;
      const sessionToken = resolver.resolve('cloud-logs', 'aws', 'AWS_SESSION_TOKEN', 'sessionToken')?.value;
      return new CloudTrailAdapter(baseUrl, accessKeyId, secretAccessKey, sessionToken);
    },
  };
}
