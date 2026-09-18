/**
 * @module main/integrations/synthetic/synthetic-factories
 *
 * AdapterFactory registrations for every synthetic adapter. These can be
 * pushed into an IntegrationRegistry next to real vendor factories.
 *
 * Each factory:
 *  - declares NO required credentials (the dataset is in-memory)
 *  - returns null if the synthetic environment is disabled via
 *    CYBER_SYNTHETIC_ENABLED env var (so the registry will report
 *    "unavailable" and real vendors remain usable)
 */

import type { AdapterFactory } from '../integration-registry';
import type { IntegrationCredentialResolver } from '../integration-credentials';
import {
  SyntheticSiemAdapter,
  SYNTHETIC_SIEM_METADATA,
} from './synthetic-siem-adapter';
import {
  SyntheticEdrAdapter,
  SYNTHETIC_EDR_METADATA,
} from './synthetic-edr-adapter';
import {
  SyntheticNetworkAdapter,
  SYNTHETIC_NETWORK_METADATA,
} from './synthetic-network-adapter';
import {
  SyntheticIdentityAdapter,
  SYNTHETIC_IDENTITY_METADATA,
} from './synthetic-identity-adapter';
import {
  SyntheticThreatIntelAdapter,
  SYNTHETIC_THREATINTEL_METADATA,
} from './synthetic-threatintel-adapter';
import {
  SyntheticFileAnalysisAdapter,
  SYNTHETIC_FILE_ANALYSIS_METADATA,
} from './synthetic-file-analysis-adapter';
import { SyntheticDatasetStore } from './synthetic-dataset';
import { SYNTHETIC_WATERMARK } from './scenario-types';

export function isSyntheticEnvironmentEnabled(): boolean {
  const flag = process.env.CYBER_SYNTHETIC_ENABLED;
  return flag === '1' || flag === 'true';
}

/**
 * Build a fresh AdapterFactory set bound to the supplied dataset store.
 * The store is shared across factories so loading a scenario populates
 * every adapter at once.
 */
export function buildSyntheticFactories(store: SyntheticDatasetStore): AdapterFactory[] {
  return [
    {
      domain: 'siem',
      vendor: 'synthetic',
      adapterId: SYNTHETIC_SIEM_METADATA.adapterId,
      requiredCredentials: [],
      build(_resolver: IntegrationCredentialResolver) {
        if (!isSyntheticEnvironmentEnabled()) return null;
        return new SyntheticSiemAdapter(store);
      },
    },
    {
      domain: 'edr',
      vendor: 'synthetic',
      adapterId: SYNTHETIC_EDR_METADATA.adapterId,
      requiredCredentials: [],
      build(_resolver: IntegrationCredentialResolver) {
        if (!isSyntheticEnvironmentEnabled()) return null;
        return new SyntheticEdrAdapter(store);
      },
    },
    {
      domain: 'network',
      vendor: 'synthetic',
      adapterId: SYNTHETIC_NETWORK_METADATA.adapterId,
      requiredCredentials: [],
      build(_resolver: IntegrationCredentialResolver) {
        if (!isSyntheticEnvironmentEnabled()) return null;
        return new SyntheticNetworkAdapter(store);
      },
    },
    {
      domain: 'identity',
      vendor: 'synthetic',
      adapterId: SYNTHETIC_IDENTITY_METADATA.adapterId,
      requiredCredentials: [],
      build(_resolver: IntegrationCredentialResolver) {
        if (!isSyntheticEnvironmentEnabled()) return null;
        return new SyntheticIdentityAdapter(store);
      },
    },
    {
      domain: 'threat-intel',
      vendor: 'synthetic',
      adapterId: SYNTHETIC_THREATINTEL_METADATA.adapterId,
      requiredCredentials: [],
      build(_resolver: IntegrationCredentialResolver) {
        if (!isSyntheticEnvironmentEnabled()) return null;
        return new SyntheticThreatIntelAdapter(store);
      },
    },
    {
      domain: 'file-analysis',
      vendor: 'synthetic',
      adapterId: SYNTHETIC_FILE_ANALYSIS_METADATA.adapterId,
      requiredCredentials: [],
      build(_resolver: IntegrationCredentialResolver) {
        if (!isSyntheticEnvironmentEnabled()) return null;
        return new SyntheticFileAnalysisAdapter(store);
      },
    },
  ];
}

export { SYNTHETIC_WATERMARK };