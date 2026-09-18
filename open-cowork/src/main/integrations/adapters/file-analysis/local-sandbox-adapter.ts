/**
 * @module main/integrations/adapters/file-analysis/local-sandbox-adapter
 *
 * Local sandbox adapter for file analysis. Reads static metadata about a
 * file from a local sandbox mount; never executes the file. Vendor-specific
 * parsing stays inside the adapter.
 */

import { existsSync, statSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import type { AdapterFactory } from '../../integration-registry';
import type { IntegrationCredentialResolver } from '../../integration-credentials';
import type { FileAnalysisAdapter, FileAnalysisReport, FileAnalysisSubmission, IntegrationMetadata, IntegrationObservation } from '../../integration-types';
import { resolveCredential } from '../../integration-registry';

export const LOCAL_SANDBOX_METADATA: IntegrationMetadata = {
  domain: 'file-analysis',
  vendor: 'local-sandbox',
  adapterId: 'local-sandbox-static',
  displayName: 'Local Sandbox (static only)',
  description: 'Local, safe, non-executing static analysis of artifacts mounted at a sandbox path.',
  capabilities: { submitFileForAnalysis: true, fetchFileReport: true },
};

export class LocalSandboxFileAnalysisAdapter implements FileAnalysisAdapter {
  readonly metadata = LOCAL_SANDBOX_METADATA;

  constructor(private readonly rootPath: string) {}

  async health() {
    if (!existsSync(this.rootPath)) {
      return { available: false, reason: `Sandbox root not found at ${this.rootPath}`, checkedAt: Date.now() };
    }
    return { available: true, checkedAt: Date.now() };
  }

  async submitFileForAnalysis(submission: FileAnalysisSubmission): Promise<IntegrationObservation<FileAnalysisReport>> {
    const fullPath = path.join(this.rootPath, submission.fileName);
    if (!existsSync(fullPath)) {
      return {
        value: { submissionId: submission.fileName, status: 'error' },
        provenance: provenance(this.metadata, 'submitFileForAnalysis'),
      };
    }
    return {
      value: { submissionId: submission.fileName, status: 'complete' },
      provenance: provenance(this.metadata, 'submitFileForAnalysis'),
    };
  }

  async fetchFileReport(submissionId: string): Promise<IntegrationObservation<FileAnalysisReport>> {
    const fullPath = path.join(this.rootPath, submissionId);
    if (!existsSync(fullPath)) {
      return {
        value: { submissionId, status: 'error' },
        provenance: provenance(this.metadata, 'fetchFileReport'),
      };
    }
    const stats = statSync(fullPath);
    const content = readFileSync(fullPath);
    const sha256 = createHash('sha256').update(content).digest('hex');
    return {
      value: {
        submissionId,
        status: 'complete',
        verdict: 'unknown',
        engines: [
          { name: 'static-size', verdict: String(stats.size) },
          { name: 'static-sha256', verdict: sha256 },
        ],
        completedAt: Date.now(),
        raw: { path: fullPath, size: stats.size, sha256 },
      },
      provenance: provenance(this.metadata, 'fetchFileReport'),
    };
  }
}

function provenance(metadata: IntegrationMetadata, capability: string) {
  return {
    domain: 'file-analysis' as const,
    adapterId: metadata.adapterId,
    vendor: metadata.vendor,
    capability,
    method: 'file_import' as const,
    collectedAt: Date.now(),
  };
}

export function createLocalSandboxFactory(): AdapterFactory {
  return {
    domain: 'file-analysis',
    vendor: 'local-sandbox',
    adapterId: 'local-sandbox-static',
    requiredCredentials: [{ envVar: 'SANDBOX_ROOT_PATH', configKey: 'rootPath' }],
    build(resolver: IntegrationCredentialResolver) {
      const rootPath = resolveCredential(resolver, 'file-analysis', 'local-sandbox', 'SANDBOX_ROOT_PATH', 'rootPath').value;
      return new LocalSandboxFileAnalysisAdapter(rootPath);
    },
  };
}
