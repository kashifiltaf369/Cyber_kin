/**
 * @module main/integrations/synthetic/synthetic-network-adapter
 *
 * Synthetic network telemetry adapter. Serves network connections and
 * DNS queries that weren't already exposed by the EDR adapter.
 */

import type {
  DnsRecord,
  EventSearchQuery,
  IntegrationCapabilities,
  IntegrationHealth,
  IntegrationMetadata,
  IntegrationObservation,
  NetworkConnectionRecord,
  NetworkTelemetryAdapter,
} from '../integration-types';
import { IntegrationUnavailableError } from '../integration-error';
import { SyntheticDatasetStore } from './synthetic-dataset';
import { observeSynthetic } from './synthetic-adapter-base';

export const SYNTHETIC_NETWORK_METADATA: IntegrationMetadata = {
  domain: 'network',
  vendor: 'synthetic',
  adapterId: 'synthetic-network',
  displayName: 'Synthetic Network Telemetry (DEMO ONLY)',
  description: 'Returns deterministic synthetic netflow/DNS records from the active demo scenario.',
  capabilities: {
    searchNetworkConnections: true,
    searchDns: true,
  } satisfies IntegrationCapabilities,
};

export class SyntheticNetworkAdapter implements NetworkTelemetryAdapter {
  readonly metadata: IntegrationMetadata = SYNTHETIC_NETWORK_METADATA;

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

  async searchConnections(
    query: EventSearchQuery & { remoteAddress?: string; host?: string },
  ): Promise<IntegrationObservation<NetworkConnectionRecord[]>> {
    this.requireLoaded();
    const dataset = this.store.requireDataset();
    return observeSynthetic(
      dataset,
      'network',
      'searchConnections',
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
      'network',
      'searchDns',
      this.store.searchDns(query),
    );
  }

  private requireLoaded(): void {
    if (!this.store.isLoaded()) {
      throw new IntegrationUnavailableError({
        domain: 'network',
        vendor: 'synthetic',
        reason: 'No synthetic scenario loaded',
        missingRequirements: ['synthetic-scenario'],
      });
    }
  }
}