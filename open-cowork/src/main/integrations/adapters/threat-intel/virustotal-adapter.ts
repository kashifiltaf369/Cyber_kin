/**
 * @module main/integrations/adapters/threat-intel/virustotal-adapter
 *
 * VirusTotal v3 indicator lookup adapter (public API). File analysis lives
 * behind a separate file-analysis adapter.
 */

import type { AdapterFactory } from '../../integration-registry';
import type { IntegrationCredentialResolver } from '../../integration-credentials';
import type { IndicatorLookupResult, IntegrationMetadata, IntegrationObservation, ThreatIntelAdapter } from '../../integration-types';
import { resolveCredential } from '../../integration-registry';
import { adapterFetch } from '../adapter-http-client';

export const VIRUSTOTAL_METADATA: IntegrationMetadata = {
  domain: 'threat-intel',
  vendor: 'virustotal',
  adapterId: 'virustotal-v3',
  displayName: 'VirusTotal (v3)',
  description: 'Look up IPs, domains, URLs, and hashes against VirusTotal.',
  capabilities: { lookupIndicator: true },
};

interface VirusTotalResponse {
  data?: {
    attributes?: {
      last_analysis_stats?: { malicious?: number; suspicious?: number; harmless?: number; undetected?: number };
      reputation?: number;
      last_modification_date?: number;
      first_submission_date?: number;
      tags?: string[];
      categories?: Record<string, string>;
    };
  };
}

type VirusTotalStats = { malicious?: number; suspicious?: number; harmless?: number; undetected?: number } | undefined;

export class VirusTotalThreatIntelAdapter implements ThreatIntelAdapter {
  readonly metadata = VIRUSTOTAL_METADATA;

  constructor(
    private readonly baseUrl: string,
    private readonly apiKey: string
  ) {}

  async health() {
    try {
      await adapterFetch({
        url: `${this.baseUrl.replace(/\/$/, '')}/users/me`,
        method: 'GET',
        headers: { 'x-apikey': this.apiKey },
        timeoutMs: 5000,
      });
      return { available: true, checkedAt: Date.now() };
    } catch (error) {
      return {
        available: false,
        reason: error instanceof Error ? error.message : 'VirusTotal health check failed',
        checkedAt: Date.now(),
      };
    }
  }

  async lookupIndicator(indicator: string): Promise<IntegrationObservation<IndicatorLookupResult>> {
    const indicatorType = classify(indicator);
    const path = buildPath(indicatorType, indicator);
    const response = await adapterFetch<VirusTotalResponse>({
      url: `${this.baseUrl.replace(/\/$/, '')}${path}`,
      method: 'GET',
      headers: { 'x-apikey': this.apiKey },
      timeoutMs: 10_000,
    });
    const stats = response.data.data?.attributes?.last_analysis_stats;
    const verdict = deriveVerdict(stats);
    const confidence = stats ? Math.min(1, ((stats.malicious || 0) + (stats.suspicious || 0)) / Math.max(1, (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0))) : 0;
    return {
      value: {
        indicator,
        indicatorType,
        verdict,
        confidence,
        categories: Object.values(response.data.data?.attributes?.categories || {}),
        sources: [this.metadata.vendor],
        firstSeen: response.data.data?.attributes?.first_submission_date ? Number(response.data.data.attributes.first_submission_date) * 1000 : undefined,
        lastSeen: response.data.data?.attributes?.last_modification_date ? Number(response.data.data.attributes.last_modification_date) * 1000 : undefined,
        raw: response.data as unknown as Record<string, unknown>,
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

function buildPath(indicatorType: IndicatorLookupResult['indicatorType'], indicator: string): string {
  switch (indicatorType) {
    case 'ip':
      return `/ip_addresses/${encodeURIComponent(indicator)}`;
    case 'domain':
      return `/domains/${encodeURIComponent(indicator)}`;
    case 'url':
      return `/urls/${encodeURIComponent(Buffer.from(indicator).toString('base64url'))}`;
    case 'hash':
      return `/files/${encodeURIComponent(indicator)}`;
    default:
      return `/search?query=${encodeURIComponent(indicator)}`;
  }
}

function deriveVerdict(stats: VirusTotalStats): IndicatorLookupResult['verdict'] {
  if (!stats) return 'unknown';
  if ((stats.malicious || 0) >= 3) return 'malicious';
  if ((stats.malicious || 0) >= 1 || (stats.suspicious || 0) >= 1) return 'suspicious';
  if ((stats.harmless || 0) > 0) return 'benign';
  return 'unknown';
}

export function createVirusTotalFactory(): AdapterFactory {
  return {
    domain: 'threat-intel',
    vendor: 'virustotal',
    adapterId: 'virustotal-v3',
    requiredCredentials: [
      { envVar: 'VIRUSTOTAL_BASE_URL', configKey: 'baseUrl' },
      { envVar: 'VIRUSTOTAL_API_KEY', configKey: 'apiKey' },
    ],
    build(resolver: IntegrationCredentialResolver) {
      const baseUrl = resolveCredential(resolver, 'threat-intel', 'virustotal', 'VIRUSTOTAL_BASE_URL', 'baseUrl').value;
      const apiKey = resolveCredential(resolver, 'threat-intel', 'virustotal', 'VIRUSTOTAL_API_KEY', 'apiKey').value;
      return new VirusTotalThreatIntelAdapter(baseUrl, apiKey);
    },
  };
}
