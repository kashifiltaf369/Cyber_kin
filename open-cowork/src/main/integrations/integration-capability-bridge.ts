/**
 * @module main/integrations/integration-capability-bridge
 *
 * Bridges vendor-neutral cyber capabilities (defined in `cyber-capability-
 * registry`) to integrations registered in `IntegrationRegistry`.
 *
 * Per CYBER_BUILD_RULES rule 26, vendor-specific integrations belong behind
 * adapters. Per rules 33-34, we don't optimize for feature count — we only
 * bridge the capabilities that benefit from a remote vendor (local files
 * keep working through the existing local executors).
 *
 * The bridge runs BEFORE the local executor and:
 *   1. Checks if any registered adapter is available for the capability.
 *   2. If yes, calls the adapter and normalizes the result back into the
 *      capability output shape.
 *   3. If no adapter is available (missing credentials, misconfigured),
 *      falls back to the local executor so investigation never crashes.
 *
 * This keeps the core investigation engine vendor-neutral: it always calls
 * `registry.execute(capabilityName, input)`; the bridge decides whether
 * that goes through a remote integration or stays local.
 */

import type {
  CyberCapabilityExecutionContext,
  CyberCapabilityName,
  CyberCapabilityRegistry,
} from '../cyber/cyber-capability-registry';
import { IntegrationUnavailableError, describeIntegrationError, isIntegrationUnavailable } from './integration-error';
import {
  type AnyIntegrationAdapter,
  type CloudLogQuery,
  type DnsRecord,
  type EventRecord,
  type EventSearchQuery,
  type FileAnalysisReport,
  type FileAnalysisSubmission,
  type IdentityActivityRecord,
  type IndicatorLookupResult,
  type IntegrationDomain,
  type IntegrationHealth,
  type IntegrationObservation,
  type NetworkConnectionRecord,
  type ProcessRecord,
  isCloudLogsAdapter,
  isEdrAdapter,
  isFileAnalysisAdapter,
  isIdentityAdapter,
  isNetworkTelemetryAdapter,
  isSiemAdapter,
  isThreatIntelAdapter,
} from './integration-types';
import { type AdapterFactory, type IntegrationRegistry } from './integration-registry';

export interface IntegrationCapabilityBridgeOptions {
  investigationId?: string;
  preferredAdapters?: Partial<Record<IntegrationDomain, string>>;
  onUnavailable?: (info: { domain: IntegrationDomain; reason: string }) => void;
}

interface CapabilityMapping {
  domain: IntegrationDomain;
  vendor?: string;
}

const DEFAULT_CAPABILITY_MAPPING: Partial<Record<CyberCapabilityName, CapabilityMapping>> = {
  search_events: { domain: 'siem' },
  search_processes: { domain: 'edr' },
  search_network_connections: { domain: 'edr' },
  search_dns: { domain: 'edr' },
  search_identity_activity: { domain: 'identity' },
  lookup_indicator: { domain: 'threat-intel' },
  inspect_file: { domain: 'file-analysis' },
  query_local_logs: { domain: 'cloud-logs' },
};

export class IntegrationCapabilityBridge {
  private readonly registry: IntegrationRegistry;
  private readonly capabilityRegistry: CyberCapabilityRegistry;
  private readonly options: IntegrationCapabilityBridgeOptions;
  private readonly capabilityMapping: Partial<Record<CyberCapabilityName, CapabilityMapping>>;

  constructor(
    registry: IntegrationRegistry,
    capabilityRegistry: CyberCapabilityRegistry,
    options: IntegrationCapabilityBridgeOptions = {}
  ) {
    this.registry = registry;
    this.capabilityRegistry = capabilityRegistry;
    this.options = options;
    this.capabilityMapping = buildMapping(registry, options);
  }

  listAvailableDomains(): IntegrationDomain[] {
    const seen = new Set<IntegrationDomain>();
    for (const mapping of Object.values(this.capabilityMapping)) {
      if (mapping) seen.add(mapping.domain);
    }
    return Array.from(seen);
  }

  async runWithAdapterFallback<Name extends CyberCapabilityName>(
    name: Name,
    input: unknown,
    context?: CyberCapabilityExecutionContext
  ): Promise<unknown> {
    const mapping = this.capabilityMapping[name];
    if (!mapping) {
      return this.capabilityRegistry.execute(name, input, context);
    }
    try {
      const adapter = await this.selectAdapter(mapping, context);
      const observation = await this.invokeAdapter(name, adapter, input);
      return normalizeObservation(name, observation);
    } catch (error) {
      if (isIntegrationUnavailable(error)) {
        this.options.onUnavailable?.({ domain: mapping.domain, reason: describeIntegrationError(error) });
        return this.capabilityRegistry.execute(name, input, context);
      }
      throw error;
    }
  }

  private async selectAdapter(
    mapping: CapabilityMapping,
    context?: CyberCapabilityExecutionContext
  ): Promise<AnyIntegrationAdapter> {
    const vendorFromContext = context?.adapterPreference?.includes(':')
      ? context.adapterPreference.split(':')[1]
      : undefined;
    const vendor = vendorFromContext || mapping.vendor;
    try {
      return await this.registry.getHealthyAdapter(mapping.domain, vendor);
    } catch (error) {
      if (isIntegrationUnavailable(error)) {
        throw new IntegrationUnavailableError({
          domain: mapping.domain,
          vendor: vendor || 'any',
          reason: error.reason,
          missingRequirements: error.missingRequirements,
        });
      }
      throw error;
    }
  }

  private async invokeAdapter(
    capabilityName: CyberCapabilityName,
    adapter: AnyIntegrationAdapter,
    input: unknown
  ): Promise<IntegrationObservation<unknown>> {
    switch (capabilityName) {
      case 'search_events': {
        if (!isSiemAdapter(adapter)) throw new IntegrationUnavailableError({ domain: 'siem', vendor: adapter.metadata.vendor, reason: 'Adapter does not support searchEvents' });
        return adapter.searchEvents((input || {}) as EventSearchQuery);
      }
      case 'search_processes': {
        if (!isEdrAdapter(adapter)) throw new IntegrationUnavailableError({ domain: 'edr', vendor: adapter.metadata.vendor, reason: 'Adapter does not support searchProcesses' });
        return adapter.searchProcesses((input || {}) as EventSearchQuery & { host?: string; name?: string });
      }
      case 'search_network_connections': {
        if (isEdrAdapter(adapter)) {
          return adapter.searchNetworkConnections((input || {}) as EventSearchQuery & { host?: string; remoteAddress?: string });
        }
        if (isNetworkTelemetryAdapter(adapter)) {
          return adapter.searchConnections((input || {}) as EventSearchQuery & { remoteAddress?: string; host?: string });
        }
        throw new IntegrationUnavailableError({ domain: 'network', vendor: adapter.metadata.vendor, reason: 'Adapter does not support searchNetworkConnections' });
      }
      case 'search_dns': {
        if (isEdrAdapter(adapter) && adapter.searchDns) {
          return adapter.searchDns((input || {}) as EventSearchQuery & { host?: string; name?: string });
        }
        if (isNetworkTelemetryAdapter(adapter)) {
          return adapter.searchDns((input || {}) as EventSearchQuery & { host?: string; name?: string });
        }
        throw new IntegrationUnavailableError({ domain: 'network', vendor: adapter.metadata.vendor, reason: 'Adapter does not support searchDns' });
      }
      case 'search_identity_activity': {
        if (!isIdentityAdapter(adapter)) throw new IntegrationUnavailableError({ domain: 'identity', vendor: adapter.metadata.vendor, reason: 'Adapter does not support queryIdentityActivity' });
        return adapter.queryIdentityActivity((input || {}) as EventSearchQuery & { actor?: string; action?: string });
      }
      case 'lookup_indicator': {
        if (!isThreatIntelAdapter(adapter)) throw new IntegrationUnavailableError({ domain: 'threat-intel', vendor: adapter.metadata.vendor, reason: 'Adapter does not support lookupIndicator' });
        const indInput = (input || {}) as { indicator?: string };
        if (!indInput.indicator) throw new IntegrationUnavailableError({ domain: 'threat-intel', vendor: adapter.metadata.vendor, reason: 'Missing indicator value' });
        return adapter.lookupIndicator(indInput.indicator);
      }
      case 'inspect_file': {
        if (!isFileAnalysisAdapter(adapter)) throw new IntegrationUnavailableError({ domain: 'file-analysis', vendor: adapter.metadata.vendor, reason: 'Adapter does not support file analysis' });
        const fileInput = (input || {}) as { filePath?: string };
        if (!fileInput.filePath) throw new IntegrationUnavailableError({ domain: 'file-analysis', vendor: adapter.metadata.vendor, reason: 'Missing file path' });
        const submission: FileAnalysisSubmission = {
          fileName: fileInput.filePath.split(/[\\/]/).pop() || 'artifact',
          contentRef: fileInput.filePath,
        };
        return adapter.submitFileForAnalysis(submission);
      }
      case 'query_local_logs': {
        if (!isCloudLogsAdapter(adapter)) throw new IntegrationUnavailableError({ domain: 'cloud-logs', vendor: adapter.metadata.vendor, reason: 'Adapter does not support queryCloudLogs' });
        const logsInput = (input || {}) as { query?: string; service?: string; eventName?: string; startTime?: number; endTime?: number; limit?: number };
        const cloudQuery: CloudLogQuery = {
          service: logsInput.service,
          eventName: logsInput.eventName,
          startTime: logsInput.startTime,
          endTime: logsInput.endTime,
          limit: logsInput.limit,
        };
        return adapter.queryCloudLogs(cloudQuery);
      }
      default: {
        throw new IntegrationUnavailableError({ domain: 'network', vendor: adapter.metadata.vendor, reason: `Capability ${capabilityName} is not bridged` });
      }
    }
  }
}

function buildMapping(
  registry: IntegrationRegistry,
  options: IntegrationCapabilityBridgeOptions
): Partial<Record<CyberCapabilityName, CapabilityMapping>> {
  const factories = (registry as unknown as { factories?: AdapterFactory[] }).factories || [];
  const availableVendors: Record<IntegrationDomain, Set<string>> = {
    siem: new Set(),
    edr: new Set(),
    network: new Set(),
    identity: new Set(),
    'threat-intel': new Set(),
    'file-analysis': new Set(),
    'cloud-logs': new Set(),
  };
  for (const factory of factories) {
    availableVendors[factory.domain].add(factory.vendor);
  }
  const mapping: Partial<Record<CyberCapabilityName, CapabilityMapping>> = {};
  for (const [capability, def] of Object.entries(DEFAULT_CAPABILITY_MAPPING) as Array<[CyberCapabilityName, CapabilityMapping]>) {
    if (availableVendors[def.domain].size === 0) continue;
    const preferred = options.preferredAdapters?.[def.domain] || def.vendor;
    mapping[capability] = { domain: def.domain, vendor: preferred };
  }
  return mapping;
}

function normalizeObservation(
  capabilityName: CyberCapabilityName,
  observation: IntegrationObservation<unknown>
): unknown {
  const provenance = observation.provenance;
  const health: IntegrationHealth = { available: true, checkedAt: provenance.collectedAt };
  switch (capabilityName) {
    case 'search_events':
      return {
        sourcePath: `integration:${provenance.adapterId}`,
        matches: (observation.value as EventRecord[]).map((event) => ({
          lineNumber: event.timestamp,
          line: `[${provenance.vendor}] ${event.source}: ${event.message}`,
          provenance,
        })),
        provenance,
        health,
      };
    case 'search_processes':
      return {
        processes: (observation.value as ProcessRecord[]).map((process) => ({ ...process, provenance })),
        provenance,
        health,
      };
    case 'search_network_connections':
      return {
        connections: (observation.value as NetworkConnectionRecord[]).map((connection) => ({ ...connection, provenance })),
        provenance,
        health,
      };
    case 'search_dns':
      return {
        records: (observation.value as DnsRecord[]).map((record) => ({
          lineNumber: record.timestamp,
          line: `[${provenance.vendor}] ${record.host || ''} -> ${record.query}`,
          provenance,
        })),
        provenance,
        health,
      };
    case 'search_identity_activity':
      return {
        sourcePath: `integration:${provenance.adapterId}`,
        matches: (observation.value as IdentityActivityRecord[]).map((record) => ({
          lineNumber: record.timestamp,
          line: `[${provenance.vendor}] ${record.actor} ${record.action} ${record.result || ''}`,
          provenance,
        })),
        provenance,
        health,
      };
    case 'lookup_indicator': {
      const lookup = observation.value as IndicatorLookupResult;
      return {
        indicator: lookup.indicator,
        indicatorType: lookup.indicatorType,
        summary: `${lookup.verdict || 'unknown'} from ${provenance.vendor}: ${(lookup.categories || []).slice(0, 5).join(', ') || 'no categories'}`,
        safeToEnrich: lookup.verdict !== 'unknown',
        provenance,
        health,
      };
    }
    case 'inspect_file': {
      const report = observation.value as FileAnalysisReport;
      return {
        path: report.submissionId,
        exists: report.status === 'complete',
        size: null,
        extension: '',
        preview: report.engines?.slice(0, 5).map((engine) => `${engine.name}=${engine.verdict}`).join('\n') || '',
        verdict: report.verdict,
        provenance,
        health,
      };
    }
    case 'query_local_logs':
      return {
        files: [],
        records: [],
        provenance,
        health,
      };
    default:
      return observation.value;
  }
}
