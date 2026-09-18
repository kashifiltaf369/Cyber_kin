/**
 * @module main/integrations/synthetic/synthetic-file-analysis-adapter
 *
 * Synthetic file-analysis adapter. Serves deterministic verdicts for
 * known submissionIds from the active scenario.
 */

import type {
  FileAnalysisReport,
  FileAnalysisSubmission,
  IntegrationCapabilities,
  IntegrationHealth,
  IntegrationMetadata,
  IntegrationObservation,
  FileAnalysisAdapter,
} from '../integration-types';
import { IntegrationUnavailableError } from '../integration-error';
import { SyntheticDatasetStore } from './synthetic-dataset';

export const SYNTHETIC_FILE_ANALYSIS_METADATA: IntegrationMetadata = {
  domain: 'file-analysis',
  vendor: 'synthetic',
  adapterId: 'synthetic-file-analysis',
  displayName: 'Synthetic File Analysis (DEMO ONLY)',
  description: 'Returns deterministic synthetic sandbox verdicts from the active demo scenario.',
  capabilities: {
    submitFileForAnalysis: true,
    fetchFileReport: true,
  } satisfies IntegrationCapabilities,
};

export class SyntheticFileAnalysisAdapter implements FileAnalysisAdapter {
  readonly metadata: IntegrationMetadata = SYNTHETIC_FILE_ANALYSIS_METADATA;

  constructor(private readonly store: SyntheticDatasetStore) {}

  async health(): Promise<IntegrationHealth> {
    if (!this.store.isLoaded()) {
      return {
        available: false,
        reason: 'No synthetic scenario loaded',
        missingRequirements: ['synthetic-scenario'],
        checkedAt: Date.now(),
      };
    }
    return { available: true, checkedAt: Date.now() };
  }

  async submitFileForAnalysis(
    submission: FileAnalysisSubmission,
  ): Promise<IntegrationObservation<FileAnalysisReport>> {
    this.requireLoaded();
    const dataset = this.store.requireDataset();
    const submissionId = `fa-${dataset.scenarioId}-${submission.fileName.replace(/[^a-z0-9]/gi, '-')}`;
    const report = this.store.fetchFileReport(submissionId) ?? this.synthesizeReport(submissionId, submission);
    return {
      value: report,
      provenance: {
        domain: 'file-analysis',
        adapterId: 'synthetic-file-analysis',
        vendor: 'synthetic',
        capability: 'submitFileForAnalysis',
        method: 'file_import',
        collectedAt: Date.now(),
        sourceLabel: `synthetic-scenario:${dataset.scenarioId}`,
        sourceId: dataset.scenarioId,
      },
    };
  }

  async fetchFileReport(submissionId: string): Promise<IntegrationObservation<FileAnalysisReport>> {
    this.requireLoaded();
    const dataset = this.store.requireDataset();
    const report = this.store.fetchFileReport(submissionId) ?? {
      submissionId,
      status: 'complete' as const,
      verdict: 'benign' as const,
      score: 5,
      engines: [{ name: 'Synthetic Sandbox', verdict: 'benign' }],
      completedAt: Date.now(),
    };
    return {
      value: {
        ...report,
        raw: { ...(report.raw ?? {}), synthetic: true, watermark: 'SYNTHETIC_DEMO_DATA' },
      },
      provenance: {
        domain: 'file-analysis',
        adapterId: 'synthetic-file-analysis',
        vendor: 'synthetic',
        capability: 'fetchFileReport',
        method: 'file_import',
        collectedAt: Date.now(),
        sourceLabel: `synthetic-scenario:${dataset.scenarioId}`,
        sourceId: dataset.scenarioId,
      },
    };
  }

  private synthesizeReport(submissionId: string, submission: FileAnalysisSubmission): FileAnalysisReport {
    return {
      submissionId,
      status: 'complete',
      verdict: 'unknown',
      score: 0,
      engines: [{ name: 'Synthetic Sandbox', verdict: 'unknown' }],
      completedAt: Date.now(),
      raw: { synthetic: true, fileName: submission.fileName },
    };
  }

  private requireLoaded(): void {
    if (!this.store.isLoaded()) {
      throw new IntegrationUnavailableError({
        domain: 'file-analysis',
        vendor: 'synthetic',
        reason: 'No synthetic scenario loaded',
        missingRequirements: ['synthetic-scenario'],
      });
    }
  }
}