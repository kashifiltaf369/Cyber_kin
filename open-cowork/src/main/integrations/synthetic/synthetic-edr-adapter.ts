/**
 * @module main/integrations/synthetic/synthetic-edr-adapter
 *
 * Synthetic EDR adapter. Serves processes, network connections, and DNS
 * from the active scenario. Mirrors CrowdStrike / Defender / SentinelOne
 * capability surface.
 */

import type {
  DnsRecord,
  EventSearchQuery,
  IntegrationCapabilities,
  IntegrationHealth,
  IntegrationMetadata,
  IntegrationObservation,
  NetworkConnectionRecord,
  ProcessRecord,
  EdrAdapter,
} from '../integration-types';
import { IntegrationUnavailableError } from '../integration-error';
import { SyntheticDatasetStore } from './synthetic-dataset';
import { observeSynthetic } from './synthetic-adapter-base';

export const SYNTHETIC_EDR_METADATA: IntegrationMetadata = {
  domain: 'edr',
  vendor: 'synthetic',
  adapterId: 'synthetic-edr',
  displayName: 'Synthetic EDR (DEMO ONLY)',
  description:
    'Returns deterministic synthetic processes, network connections, and DNS from the active demo scenario.',
  capabilities: {
    searchProcesses: true,
    searchNetworkConnections: true,
    searchDns: true,
  } satisfies IntegrationCapabilities,
};

export class SyntheticEdrAdapter implements EdrAdapter {
  readonly metadata: IntegrationMetadata = SYNTHETIC_EDR_METADATA;

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

  async searchProcesses(
    query: EventSearchQuery & { host?: string; name?: string },
  ): Promise<IntegrationObservation<ProcessRecord[]>> {
    this.requireLoaded();
    const dataset = this.store.requireDataset();
    return observeSynthetic(
      dataset,
      'edr',
      'searchProcesses',
      this.store.searchProcesses(query),
    );
  }

  async searchNetworkConnections(
    query: EventSearchQuery & { host?: string; remoteAddress?: string },
  ): Promise<IntegrationObservation<NetworkConnectionRecord[]>> {
    this.requireLoaded();
    const dataset = this.store.requireDataset();
    return observeSynthetic(
      dataset,
      'edr',
      'searchNetworkConnections',
      this.store.searchNetworkConnections(query),
    );
  }

  async searchDns(
    query: EventSearchQuery & { host?: string; name?: string },
  ): Promise<IntegrationObservation<DnsRecord[]>> {
    this.requireLoaded();
    const dataset = this.store.requireDataset();
    return observeSynthetic(
      dataset,
      'edr',
      'searchDns',
      this.store.searchDns(query),
    );
  }

  private requireLoaded(): void {
    if (!this.store.isLoaded()) {
      throw new IntegrationUnavailableError({
        domain: 'edr',
        vendor: 'synthetic',
        reason: 'No synthetic scenario loaded',
        missingRequirements: ['synthetic-scenario'],
      });
    }
  }
}