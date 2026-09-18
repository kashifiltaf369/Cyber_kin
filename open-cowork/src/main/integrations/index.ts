/**
 * @module main/integrations
 *
 * Vendor-neutral integration boundary for cybersecurity systems.
 *
 * Exports:
 *   - `createDefaultIntegrationRegistry`: builds a registry pre-loaded with
 *     one adapter per domain (SIEM/EDR/Network/Identity/Threat-Intel/
 *     File-Analysis/Cloud-Logs). Each adapter self-describes the credentials
 *     it needs; missing credentials make the integration unavailable
 *     gracefully instead of crashing the investigation engine.
 *   - `IntegrationCapabilityBridge`: routes cyber capability calls through
 *     the registry when an adapter is available, falling back to local
 *     executors when not.
 *
 * Per CYBER_BUILD_RULES rule 26, vendor-specific implementations live in
 * `adapters/*` and never leak into the investigation engine. Per rule 20,
 * no secrets are logged; per rule 23, adapters never fabricate evidence.
 */

import {
  type AdapterFactory,
  type IntegrationRegistryOptions,
  IntegrationRegistry,
} from './integration-registry';
import {
  createCloudTrailFactory,
  createAzureActivityFactory,
  createGcpAuditFactory,
} from './adapters/cloud-logs';
import {
  createCrowdStrikeFactory,
  createDefenderFactory,
  createSentinelOneFactory,
} from './adapters/edr';
import { createEntraFactory, createOktaFactory } from './adapters/identity';
import { createPcapExportFactory, createZeekFactory } from './adapters/network';
import { createLocalSandboxFactory, createVirusTotalFileFactory } from './adapters/file-analysis';
import { createMispFactory, createVirusTotalFactory } from './adapters/threat-intel';
import { createElasticFactory, createSentinelFactory, createSplunkFactory } from './adapters/siem';

export const DEFAULT_INTEGRATION_PREFERENCE: Required<Record<keyof typeof DEFAULT_INTEGRATION_VENDORS, string>> = {
  siem: 'splunk',
  edr: 'crowdstrike',
  network: 'zeek',
  identity: 'entra',
  'threat-intel': 'virustotal',
  'file-analysis': 'local-sandbox',
  'cloud-logs': 'aws',
};

export const DEFAULT_INTEGRATION_VENDORS = {
  siem: ['splunk', 'elastic', 'sentinel'],
  edr: ['crowdstrike', 'sentinelone', 'defender'],
  network: ['zeek', 'pcap-export'],
  identity: ['entra', 'okta'],
  'threat-intel': ['virustotal', 'misp'],
  'file-analysis': ['local-sandbox', 'virustotal'],
  'cloud-logs': ['aws', 'gcp', 'azure'],
} as const;

export const DEFAULT_INTEGRATION_FACTORIES: AdapterFactory[] = [
  createSplunkFactory(),
  createElasticFactory(),
  createSentinelFactory(),
  createCrowdStrikeFactory(),
  createSentinelOneFactory(),
  createDefenderFactory(),
  createZeekFactory(),
  createPcapExportFactory(),
  createEntraFactory(),
  createOktaFactory(),
  createVirusTotalFactory(),
  createMispFactory(),
  createVirusTotalFileFactory(),
  createLocalSandboxFactory(),
  createCloudTrailFactory(),
  createGcpAuditFactory(),
  createAzureActivityFactory(),
];

export function createDefaultIntegrationRegistry(
  options: IntegrationRegistryOptions & { factories?: AdapterFactory[] } = {}
): IntegrationRegistry {
  const registry = new IntegrationRegistry({
    credentials: options.credentials,
    preference: { ...DEFAULT_INTEGRATION_PREFERENCE, ...(options.preference || {}) },
    healthCacheMs: options.healthCacheMs,
  });
  registry.registerAll(options.factories || DEFAULT_INTEGRATION_FACTORIES);
  return registry;
}

export * from './integration-types';
export * from './integration-error';
export * from './integration-credentials';
export * from './integration-registry';
export * from './integration-capability-bridge';
export * from './adapters';
