/**
 * @module main/integrations/synthetic/synthetic-identity-adapter
 *
 * Synthetic identity/IdP adapter. Serves authentication events (logons,
 * MFA, group changes, cloud uploads) for the active scenario.
 */

import type {
  EventSearchQuery,
  IdentityActivityRecord,
  IntegrationCapabilities,
  IntegrationHealth,
  IntegrationMetadata,
  IntegrationObservation,
  IdentityAdapter,
} from '../integration-types';
import { IntegrationUnavailableError } from '../integration-error';
import { SyntheticDatasetStore } from './synthetic-dataset';
import { observeSynthetic } from './synthetic-adapter-base';

export const SYNTHETIC_IDENTITY_METADATA: IntegrationMetadata = {
  domain: 'identity',
  vendor: 'synthetic',
  adapterId: 'synthetic-identity',
  displayName: 'Synthetic Identity Provider (DEMO ONLY)',
  description: 'Returns deterministic synthetic authentication events from the active demo scenario.',
  capabilities: { searchIdentityActivity: true } satisfies IntegrationCapabilities,
};

export class SyntheticIdentityAdapter implements IdentityAdapter {
  readonly metadata: IntegrationMetadata = SYNTHETIC_IDENTITY_METADATA;

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

  async queryIdentityActivity(
    query: EventSearchQuery & { actor?: string; action?: string },
  ): Promise<IntegrationObservation<IdentityActivityRecord[]>> {
    this.requireLoaded();
    const dataset = this.store.requireDataset();
    return observeSynthetic(
      dataset,
      'identity',
      'queryIdentityActivity',
      this.store.searchIdentityActivity(query),
    );
  }

  private requireLoaded(): void {
    if (!this.store.isLoaded()) {
      throw new IntegrationUnavailableError({
        domain: 'identity',
        vendor: 'synthetic',
        reason: 'No synthetic scenario loaded',
        missingRequirements: ['synthetic-scenario'],
      });
    }
  }
}