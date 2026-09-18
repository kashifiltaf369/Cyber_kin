/**
 * @module main/integrations/synthetic/synthetic-siem-adapter
 *
 * Synthetic SIEM adapter that serves events from the active scenario's
 * dataset. Implements the vendor-neutral SiemAdapter interface so the
 * investigation engine queries it identically to real SIEMs (Splunk,
 * Sentinel, Elastic).
 */

import type {
  EventRecord,
  EventSearchQuery,
  IntegrationCapabilities,
  IntegrationHealth,
  IntegrationMetadata,
  IntegrationObservation,
  SiemAdapter,
} from '../integration-types';
import { IntegrationUnavailableError } from '../integration-error';
import { SyntheticDatasetStore } from './synthetic-dataset';
import { observeSynthetic, syntheticProvenance } from './synthetic-adapter-base';
import { SYNTHETIC_WATERMARK } from './scenario-types';

export const SYNTHETIC_SIEM_METADATA: IntegrationMetadata = {
  domain: 'siem',
  vendor: 'synthetic',
  adapterId: 'synthetic-siem',
  displayName: 'Synthetic SIEM (DEMO ONLY — not real telemetry)',
  description:
    'Returns deterministic synthetic events from the active demo scenario. All records are watermarked SYNTHETIC_DEMO_DATA.',
  capabilities: { searchEvents: true } satisfies IntegrationCapabilities,
};

export class SyntheticSiemAdapter implements SiemAdapter {
  readonly metadata: IntegrationMetadata = SYNTHETIC_SIEM_METADATA;

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

  async searchEvents(query: EventSearchQuery): Promise<IntegrationObservation<EventRecord[]>> {
    if (!this.store.isLoaded()) {
      throw new IntegrationUnavailableError({
        domain: 'siem',
        vendor: 'synthetic',
        reason: 'No synthetic scenario loaded. Load a scenario first.',
        missingRequirements: ['synthetic-scenario'],
      });
    }
    const dataset = this.store.requireDataset();
    const records = this.store.searchEvents(query);
    const observation = observeSynthetic(dataset, 'siem', 'searchEvents', records);
    return {
      ...observation,
      provenance: {
        ...observation.provenance,
        sourceLabel: `${SYNTHETIC_WATERMARK}:${dataset.scenarioId}`,
      },
    };
  }

  /**
   * Convenience for callers that don't need the full provenance envelope.
   */
  async searchEventsLight(query: EventSearchQuery): Promise<EventRecord[]> {
    if (!this.store.isLoaded()) {
      return [];
    }
    return this.store.searchEvents(query);
  }

  provenanceForScenario(capability: string): ReturnType<typeof syntheticProvenance> {
    return syntheticProvenance('siem', capability, this.store.currentScenarioId() ?? 'unknown');
  }
}