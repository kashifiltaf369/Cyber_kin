/**
 * @module main/integrations/adapters/file-analysis/virustotal-file-adapter
 *
 * VirusTotal file analysis adapter (submit + poll for report).
 */

import { readFileSync } from 'node:fs';
import type { AdapterFactory } from '../../integration-registry';
import type { IntegrationCredentialResolver } from '../../integration-credentials';
import type { FileAnalysisAdapter, FileAnalysisReport, FileAnalysisSubmission, IntegrationMetadata, IntegrationObservation } from '../../integration-types';
import { resolveCredential } from '../../integration-registry';
import { adapterFetch } from '../adapter-http-client';

export const VIRUSTOTAL_FILE_METADATA: IntegrationMetadata = {
  domain: 'file-analysis',
  vendor: 'virustotal',
  adapterId: 'virustotal-files',
  displayName: 'VirusTotal (File Analysis)',
  description: 'Submit files to VirusTotal and retrieve analysis reports.',
  capabilities: { submitFileForAnalysis: true, fetchFileReport: true },
};

interface VirusTotalSubmitResponse {
  data?: { id?: string; type?: string };
}

interface VirusTotalAnalysisResponse {
  data?: {
    id?: string;
    attributes?: {
      status?: string;
      stats?: { malicious?: number; suspicious?: number; harmless?: number; undetected?: number };
      results?: Record<string, { result?: string; category?: string }>;
      date?: number;
    };
  };
}

type VirusTotalAnalysisStats = { malicious?: number; suspicious?: number; harmless?: number; undetected?: number } | undefined;

export class VirusTotalFileAnalysisAdapter implements FileAnalysisAdapter {
  readonly metadata = VIRUSTOTAL_FILE_METADATA;

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
        reason: error instanceof Error ? error.message : 'VirusTotal file analysis health check failed',
        checkedAt: Date.now(),
      };
    }
  }

  async submitFileForAnalysis(submission: FileAnalysisSubmission): Promise<IntegrationObservation<FileAnalysisReport>> {
    const content = readFileSync(submission.contentRef);
    const response = await adapterFetch<VirusTotalSubmitResponse>({
      url: `${this.baseUrl.replace(/\/$/, '')}/files`,
      method: 'POST',
      headers: { 'x-apikey': this.apiKey },
      body: content.toString('base64'),
      timeoutMs: 30_000,
    });
    const analysisId = response.data.data?.id;
    if (!analysisId) {
      return { value: { submissionId: 'unknown', status: 'error' }, provenance: provenance(this.metadata, 'submitFileForAnalysis') };
    }
    return { value: { submissionId: analysisId, status: 'queued' }, provenance: provenance(this.metadata, 'submitFileForAnalysis') };
  }

  async fetchFileReport(submissionId: string): Promise<IntegrationObservation<FileAnalysisReport>> {
    const response = await adapterFetch<VirusTotalAnalysisResponse>({
      url: `${this.baseUrl.replace(/\/$/, '')}/analyses/${encodeURIComponent(submissionId)}`,
      method: 'GET',
      headers: { 'x-apikey': this.apiKey },
      timeoutMs: 15_000,
    });
    const attributes = response.data.data?.attributes;
    const stats = attributes?.stats;
    const engines = Object.entries(attributes?.results || {}).map(([name, value]) => ({
      name,
      verdict: String(value.result || value.category || 'unknown'),
    }));
    const verdict = deriveVerdict(stats);
    return {
      value: {
        submissionId,
        status: mapStatus(attributes?.status),
        verdict,
        score: stats ? (stats.malicious || 0) / Math.max(1, (stats.malicious || 0) + (stats.harmless || 0) + (stats.undetected || 0)) : 0,
        engines,
        completedAt: attributes?.date ? Number(attributes.date) * 1000 : undefined,
        raw: response.data as unknown as Record<string, unknown>,
      },
      provenance: provenance(this.metadata, 'fetchFileReport'),
    };
  }
}

function mapStatus(status: string | undefined): FileAnalysisReport['status'] {
  switch (status) {
    case 'queued':
      return 'queued';
    case 'running':
    case 'in-progress':
      return 'running';
    case 'completed':
      return 'complete';
    case 'error':
      return 'error';
    default:
      return 'queued';
  }
}

function deriveVerdict(stats: VirusTotalAnalysisStats): FileAnalysisReport['verdict'] {
  if (!stats) return 'unknown';
  if ((stats.malicious || 0) >= 3) return 'malicious';
  if ((stats.malicious || 0) >= 1) return 'suspicious';
  if ((stats.harmless || 0) > 0) return 'benign';
  return 'unknown';
}

function provenance(metadata: IntegrationMetadata, capability: string) {
  return {
    domain: 'file-analysis' as const,
    adapterId: metadata.adapterId,
    vendor: metadata.vendor,
    capability,
    method: 'api_query' as const,
    collectedAt: Date.now(),
  };
}

export function createVirusTotalFileFactory(): AdapterFactory {
  return {
    domain: 'file-analysis',
    vendor: 'virustotal',
    adapterId: 'virustotal-files',
    requiredCredentials: [
      { envVar: 'VIRUSTOTAL_BASE_URL', configKey: 'baseUrl' },
      { envVar: 'VIRUSTOTAL_API_KEY', configKey: 'apiKey' },
    ],
    build(resolver: IntegrationCredentialResolver) {
      const baseUrl = resolveCredential(resolver, 'file-analysis', 'virustotal', 'VIRUSTOTAL_BASE_URL', 'baseUrl').value;
      const apiKey = resolveCredential(resolver, 'file-analysis', 'virustotal', 'VIRUSTOTAL_API_KEY', 'apiKey').value;
      return new VirusTotalFileAnalysisAdapter(baseUrl, apiKey);
    },
  };
}
