/**
 * @module main/integrations/adapters/threat-intel/misp-adapter
 *
 * MISP (Malware Information Sharing Platform) indicator lookup adapter.
 */

import type { AdapterFactory } from '../../integration-registry';
import type { IntegrationCredentialResolver } from '../../integration-credentials';
import type { IndicatorLookupResult, IntegrationMetadata, IntegrationObservation, ThreatIntelAdapter } from '../../integration-types';
import { resolveCredential } from '../../integration-registry';
import { adapterFetch } from '../adapter-http-client';

export const MISP_METADATA: IntegrationMetadata = {
  domain: 'threat-intel',
  vendor: 'misp',
  adapterId: 'misp-rest',
  displayName: 'MISP (REST)',
  description: 'Look up indicators (IoCs) against a MISP instance via the REST API.',
  capabilities: { lookupIndicator: true },
};

interface MispResponse {
  response?: {
    Attribute?: Array<{
      value?: string;
      type?: string;
      to_ids?: boolean;
      timestamp?: string;
      comment?: string;
      Event?: { Tag?: Array<{ name?: string }> };
    }>;
  };
}

export class MispThreatIntelAdapter implements ThreatIntelAdapter {
  readonly metadata = MISP_METADATA;

  constructor(
    private readonly baseUrl: string,
    private readonly apiKey: string
  ) {}

  async health() {
    try {
      await adapterFetch({
        url: `${this.baseUrl.replace(/\/$/, '')}/servers/getVersion`,
        method: 'POST',
        headers: { Authorization: this.apiKey, Accept: 'application/json' },
        body: {},
        timeoutMs: 5000,
      });
      return { available: true, checkedAt: Date.now() };
    } catch (error) {
      return {
        available: false,
        reason: error instanceof Error ? error.message : 'MISP health check failed',
        checkedAt: Date.now(),
      };
    }
  }

  async lookupIndicator(indicator: string): Promise<IntegrationObservation<IndicatorLookupResult>> {
    const url = `${this.baseUrl.replace(/\/$/, '')}/attributes/restSearch`;
    const response = await adapterFetch<MispResponse>({
      url,
      method: 'POST',
      headers: { Authorization: this.apiKey, Accept: 'application/json', 'Content-Type': 'application/json' },
      body: { value: indicator, to_ids: true, includeEventTags: true },
      timeoutMs: 10_000,
    });
    const attributes = response.data.response?.Attribute || [];
    const tags = new Set<string>();
    let firstSeen: number | undefined;
    let lastSeen: number | undefined;
    for (const attr of attributes) {
      for (const tag of attr.Event?.Tag || []) {
        if (tag.name) tags.add(tag.name);
      }
      if (attr.timestamp) {
        const ts = Number(attr.timestamp) * 1000;
        if (!firstSeen || ts < firstSeen) firstSeen = ts;
        if (!lastSeen || ts > lastSeen) lastSeen = ts;
      }
    }
    const verdict = deriveVerdict(Array.from(tags));
    return {
      value: {
        indicator,
        indicatorType: classify(indicator),
        verdict,
        confidence: attributes.length > 0 ? Math.min(1, 0.3 + attributes.length * 0.1) : 0,
        categories: Array.from(tags),
        sources: [this.metadata.vendor],
        firstSeen,
        lastSeen,
        raw: attributes as unknown as Record<string, unknown>,
      },
      provenance: {
        domain: 'threat-intel',
        adapterId: this.metadata.adapterId,
        vendor: this.metadata.vendor,
        capability: 'lookupIndicator',
        method: 'api_query',
        collectedAt: Date.now(),
      },
    };
  }
}

function classify(value: string): IndicatorLookupResult['indicatorType'] {
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';
  if (/^https?:\/\//i.test(value)) return 'url';
  if (/^[a-f0-9]{32,128}$/i.test(value)) return 'hash';
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) return 'domain';
  return 'unknown';
}

function deriveVerdict(tags: string[]): IndicatorLookupResult['verdict'] {
  if (tags.some((t) => /malicious|c2|ransomware|exploit/i.test(t))) return 'malicious';
  if (tags.some((t) => /suspicious|phishing|spam/i.test(t))) return 'suspicious';
  if (tags.length === 0) return 'unknown';
  return 'unknown';
}

export function createMispFactory(): AdapterFactory {
  return {
    domain: 'threat-intel',
    vendor: 'misp',
    adapterId: 'misp-rest',
    requiredCredentials: [
      { envVar: 'MISP_BASE_URL', configKey: 'baseUrl' },
      { envVar: 'MISP_API_KEY', configKey: 'apiKey' },
    ],
    build(resolver: IntegrationCredentialResolver) {
      const baseUrl = resolveCredential(resolver, 'threat-intel', 'misp', 'MISP_BASE_URL', 'baseUrl').value;
      const apiKey = resolveCredential(resolver, 'threat-intel', 'misp', 'MISP_API_KEY', 'apiKey').value;
      return new MispThreatIntelAdapter(baseUrl, apiKey);
    },
  };
}
