/**
 * @module main/integrations/integration-registry
 *
 * Central registry that mediates adapter lookup, availability tracking, and
 * graceful unavailability reporting for the investigation engine.
 *
 * The core investigation engine ONLY ever talks to this registry. Adapters
 * register themselves by domain+vendor and the registry determines which
 * adapter is selected based on explicit preference, default preference, or
 * the first healthy one.
 *
 * Missing credentials / misconfiguration MUST produce an
 * `IntegrationUnavailableError` rather than a crash so the UI can render the
 * integration as "unavailable" and the agent can fall back to local
 * capabilities (CYBER_BUILD_RULES: graceful degradation).
 */

import {
  IntegrationUnavailableError,
  describeIntegrationError,
  isIntegrationUnavailable,
} from './integration-error';
import {
  IntegrationCredentialResolver,
  type CredentialResolverOptions,
  type ResolvedCredential,
} from './integration-credentials';
import {
  INTEGRATION_DOMAINS,
  type AnyIntegrationAdapter,
  type IntegrationDomain,
  type IntegrationHealth,
  type IntegrationMetadata,
} from './integration-types';

export interface AdapterFactory {
  domain: IntegrationDomain;
  vendor: string;
  adapterId: string;
  requiredCredentials: Array<{ envVar: string; configKey?: string }>;
  build(resolver: IntegrationCredentialResolver): AnyIntegrationAdapter | null;
}

export interface IntegrationRegistryStatusEntry {
  metadata: IntegrationMetadata;
  available: boolean;
  reason?: string;
  missingRequirements?: string[];
  checkedAt: number;
}

export interface IntegrationRegistryStatus {
  checkedAt: number;
  domains: Record<IntegrationDomain, IntegrationRegistryStatusEntry[]>;
}

export interface IntegrationRegistryOptions {
  credentials?: CredentialResolverOptions;
  preference?: Partial<Record<IntegrationDomain, string>>;
  healthCacheMs?: number;
}

export class IntegrationRegistry {
  private readonly factories: AdapterFactory[] = [];
  private readonly credentialResolver: IntegrationCredentialResolver;
  private readonly preference: Partial<Record<IntegrationDomain, string>>;
  private readonly healthCacheMs: number;
  private readonly healthCache = new Map<string, { checkedAt: number; health: IntegrationHealth }>();

  constructor(options: IntegrationRegistryOptions = {}) {
    this.credentialResolver = new IntegrationCredentialResolver(options.credentials || {});
    this.preference = options.preference ? { ...options.preference } : {};
    this.healthCacheMs = options.healthCacheMs ?? 30_000;
  }

  register(factory: AdapterFactory): void {
    this.factories.push(factory);
  }

  registerAll(factories: AdapterFactory[]): void {
    for (const factory of factories) this.factories.push(factory);
  }

  getCredentialResolver(): IntegrationCredentialResolver {
    return this.credentialResolver;
  }

  listAdapters(): IntegrationMetadata[] {
    return this.factories.map((factory) => this.buildMetadata(factory));
  }

  status(): IntegrationRegistryStatus {
    const checkedAt = Date.now();
    const domains = {} as Record<IntegrationDomain, IntegrationRegistryStatusEntry[]>;
    for (const domain of INTEGRATION_DOMAINS) {
      domains[domain] = this.factories
        .filter((factory) => factory.domain === domain)
        .map((factory) => this.evaluateFactory(factory, checkedAt));
    }
    return { checkedAt, domains };
  }

  getAdapter(domain: IntegrationDomain, vendor?: string): AnyIntegrationAdapter {
    const candidates = this.factories.filter((factory) => factory.domain === domain);
    if (candidates.length === 0) {
      throw new IntegrationUnavailableError({
        domain,
        vendor: vendor || 'unknown',
        reason: `No adapters registered for domain ${domain}`,
      });
    }
    const preferredVendor = vendor || this.preference[domain];
    const ordered = preferredVendor
      ? [
          ...candidates.filter((candidate) => candidate.vendor === preferredVendor),
          ...candidates.filter((candidate) => candidate.vendor !== preferredVendor),
        ]
      : candidates;
    const errors: string[] = [];
    for (const factory of ordered) {
      try {
        const adapter = this.buildOrThrow(factory);
        if (adapter) return adapter;
      } catch (error) {
        if (isIntegrationUnavailable(error)) {
          errors.push(`${factory.vendor}: ${error.reason}`);
          continue;
        }
        throw error;
      }
    }
    throw new IntegrationUnavailableError({
      domain,
      vendor: preferredVendor || 'any',
      reason: `No healthy adapter available for ${domain}: ${errors.join('; ') || 'no candidates'}`,
      missingRequirements: this.collectMissingRequirements(ordered),
    });
  }

  async getHealthyAdapter(domain: IntegrationDomain, vendor?: string): Promise<AnyIntegrationAdapter> {
    const adapter = this.getAdapter(domain, vendor);
    const health = await this.checkHealth(adapter);
    if (!health.available) {
      throw new IntegrationUnavailableError({
        domain,
        vendor: adapter.metadata.vendor,
        reason: health.reason || 'Health check failed',
        missingRequirements: health.missingRequirements,
      });
    }
    return adapter;
  }

  listAvailable(domain?: IntegrationDomain): IntegrationMetadata[] {
    const now = Date.now();
    return this.factories
      .filter((factory) => !domain || factory.domain === domain)
      .filter((factory) => this.evaluateFactory(factory, now).available)
      .map((factory) => this.buildMetadata(factory));
  }

  invalidateHealth(): void {
    this.healthCache.clear();
  }

  private buildMetadata(factory: AdapterFactory): IntegrationMetadata {
    return {
      domain: factory.domain,
      vendor: factory.vendor,
      adapterId: factory.adapterId,
      displayName: `${factory.vendor} (${factory.adapterId})`,
      description: `${factory.domain} integration via ${factory.vendor}`,
      capabilities: this.inferCapabilities(factory),
    };
  }

  private inferCapabilities(factory: AdapterFactory): IntegrationMetadata['capabilities'] {
    const id = factory.adapterId.toLowerCase();
    const caps: IntegrationMetadata['capabilities'] = {};
    if (factory.domain === 'siem') {
      caps.searchEvents = true;
    }
    if (factory.domain === 'edr') {
      caps.searchProcesses = true;
      caps.searchNetworkConnections = true;
      if (id.includes('dns') || id.includes('full')) caps.searchDns = true;
    }
    if (factory.domain === 'network') {
      caps.searchNetworkConnections = true;
      caps.searchDns = true;
    }
    if (factory.domain === 'identity') {
      caps.searchIdentityActivity = true;
    }
    if (factory.domain === 'threat-intel') {
      caps.lookupIndicator = true;
    }
    if (factory.domain === 'file-analysis') {
      caps.submitFileForAnalysis = true;
      caps.fetchFileReport = true;
    }
    if (factory.domain === 'cloud-logs') {
      caps.queryCloudLogs = true;
    }
    return caps;
  }

  private evaluateFactory(factory: AdapterFactory, checkedAt: number): IntegrationRegistryStatusEntry {
    const metadata = this.buildMetadata(factory);
    const missing = this.credentialResolver.missingRequirements(factory.domain, factory.vendor, factory.requiredCredentials);
    if (missing.length > 0) {
      return {
        metadata,
        available: false,
        reason: 'Missing required credentials',
        missingRequirements: missing,
        checkedAt,
      };
    }
    return { metadata, available: true, checkedAt };
  }

  private buildOrThrow(factory: AdapterFactory): AnyIntegrationAdapter | null {
    const credentials = this.credentialResolver.resolveMany(factory.domain, factory.vendor, factory.requiredCredentials);
    if (!credentials) {
      throw new IntegrationUnavailableError({
        domain: factory.domain,
        vendor: factory.vendor,
        reason: 'Missing required credentials',
        missingRequirements: this.credentialResolver.missingRequirements(factory.domain, factory.vendor, factory.requiredCredentials),
      });
    }
    const adapter = factory.build(this.credentialResolver);
    if (!adapter) {
      throw new IntegrationUnavailableError({
        domain: factory.domain,
        vendor: factory.vendor,
        reason: 'Adapter factory returned null',
      });
    }
    return adapter;
  }

  private async checkHealth(adapter: AnyIntegrationAdapter): Promise<IntegrationHealth> {
    const cached = this.healthCache.get(adapter.metadata.adapterId);
    if (cached && Date.now() - cached.checkedAt < this.healthCacheMs) {
      return cached.health;
    }
    let health: IntegrationHealth;
    try {
      health = await adapter.health();
    } catch (error) {
      health = {
        available: false,
        reason: describeIntegrationError(error),
        checkedAt: Date.now(),
      };
    }
    this.healthCache.set(adapter.metadata.adapterId, { checkedAt: Date.now(), health });
    return health;
  }

  private collectMissingRequirements(factories: AdapterFactory[]): string[] {
    const seen = new Set<string>();
    for (const factory of factories) {
      for (const req of this.credentialResolver.missingRequirements(factory.domain, factory.vendor, factory.requiredCredentials)) {
        seen.add(req);
      }
    }
    return Array.from(seen);
  }
}

export function resolveCredential(resolver: IntegrationCredentialResolver, domain: string, vendor: string, envVar: string, configKey?: string): ResolvedCredential {
  const resolved = resolver.resolve(domain, vendor, envVar, configKey);
  if (!resolved) {
    throw new IntegrationUnavailableError({
      domain: domain as IntegrationDomain,
      vendor,
      reason: `Missing credential ${envVar}`,
      missingRequirements: [envVar],
    });
  }
  return resolved;
}
