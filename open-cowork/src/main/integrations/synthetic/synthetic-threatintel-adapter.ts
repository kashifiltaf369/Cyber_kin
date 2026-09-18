/**
 * @module main/integrations/synthetic/synthetic-threatintel-adapter
 *
 * Synthetic threat intel adapter. Serves IndicatorLookupResult records
 * from the active scenario. No external HTTP calls.
 */

import type {
  IndicatorLookupResult,
  IntegrationCapabilities,
  IntegrationHealth,
  IntegrationMetadata,
  IntegrationObservation,
  ThreatIntelAdapter,
} from '../integration-types';
import { IntegrationUnavailableError } from '../integration-error';
import { SyntheticDatasetStore } from './synthetic-dataset';

export const SYNTHETIC_THREATINTEL_METADATA: IntegrationMetadata = {
  domain: 'threat-intel',
  vendor: 'synthetic',
  adapterId: 'synthetic-threatintel',
  displayName: 'Synthetic Threat Intel (DEMO ONLY)',
  description: 'Returns deterministic synthetic indicator verdicts from the active demo scenario.',
  capabilities: { lookupIndicator: true } satisfies IntegrationCapabilities,
};

export class SyntheticThreatIntelAdapter implements ThreatIntelAdapter {
  readonly metadata: IntegrationMetadata = SYNTHETIC_THREATINTEL_METADATA;

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

  async lookupIndicator(indicator: string): Promise<IntegrationObservation<IndicatorLookupResult>> {
    this.requireLoaded();
    const dataset = this.store.requireDataset();
    const result = this.store.lookupIndicator(indicator) ?? {
      indicator,
      indicatorType: 'unknown' as const,
      verdict: 'unknown' as const,
      sources: ['synthetic-feed'],
    };
    return {
      value: {
        ...result,
        raw: { ...(result.raw ?? {}), synthetic: true, watermark: 'SYNTHETIC_DEMO_DATA' },
      },
      provenance: {
        domain: 'threat-intel',
        adapterId: 'synthetic-threatintel',
        vendor: 'synthetic',
        capability: 'lookupIndicator',
        method: 'file_import',
        collectedAt: Date.now(),
        sourceLabel: `synthetic-scenario:${dataset.scenarioId}`,
        sourceId: dataset.scenarioId,
      },
    };
  }

  private requireLoaded(): void {
    if (!this.store.isLoaded()) {
      throw new IntegrationUnavailableError({
        domain: 'threat-intel',
        vendor: 'synthetic',
        reason: 'No synthetic scenario loaded',
        missingRequirements: ['synthetic-scenario'],
      });
    }
  }
}