import { describe, expect, it } from 'vitest';
import {
  createDefaultIntegrationRegistry,
  IntegrationRegistry,
  IntegrationUnavailableError,
  isIntegrationUnavailable,
} from '../src/main/integrations';

describe('IntegrationRegistry', () => {
  it('marks adapters unavailable when credentials are missing', () => {
    const registry = createDefaultIntegrationRegistry();
    const status = registry.status();
    expect(status.domains.siem.length).toBeGreaterThan(0);
    for (const entry of status.domains.siem) {
      expect(entry.available).toBe(false);
      expect(entry.reason).toBe('Missing required credentials');
      expect(entry.missingRequirements?.length || 0).toBeGreaterThan(0);
    }
    expect(status.domains.edr.every((entry) => !entry.available)).toBe(true);
    expect(status.domains['threat-intel'].every((entry) => !entry.available)).toBe(true);
    expect(status.domains['file-analysis'].every((entry) => !entry.available)).toBe(true);
    expect(status.domains['cloud-logs'].every((entry) => !entry.available)).toBe(true);
    expect(status.domains.identity.every((entry) => !entry.available)).toBe(true);
    expect(status.domains.network.every((entry) => !entry.available)).toBe(true);
  });

  it('returns available adapters when credentials are present', () => {
    const env: NodeJS.ProcessEnv = {
      SPLUNK_BASE_URL: 'https://splunk.example.com',
      SPLUNK_TOKEN: 'token',
      SPLUNK_INDEX: 'main',
      CROWDSTRIKE_BASE_URL: 'https://falcon.example.com',
      CROWDSTRIKE_TOKEN: 'token',
      ZEEK_CONN_LOG_PATH: '/tmp/conn.log',
      GRAPH_BASE_URL: 'https://graph.example.com',
      GRAPH_TOKEN: 'token',
      VIRUSTOTAL_BASE_URL: 'https://vt.example.com',
      VIRUSTOTAL_API_KEY: 'key',
      SANDBOX_ROOT_PATH: '/tmp/sandbox',
      AWS_CLOUDTRAIL_BASE_URL: 'https://cloudtrail.example.com',
      AWS_ACCESS_KEY_ID: 'AKIA',
      AWS_SECRET_ACCESS_KEY: 'secret',
    };
    const registry = createDefaultIntegrationRegistry({ credentials: { env } });
    const available = registry.listAvailable();
    expect(available.length).toBeGreaterThan(0);
    expect(available.find((meta) => meta.domain === 'siem')).toBeDefined();
    expect(available.find((meta) => meta.domain === 'edr')).toBeDefined();
    expect(available.find((meta) => meta.domain === 'network')).toBeDefined();
  });

  it('throws IntegrationUnavailableError when requesting an unavailable domain', () => {
    const registry = createDefaultIntegrationRegistry();
    expect(() => registry.getAdapter('siem')).toThrow(IntegrationUnavailableError);
    try {
      registry.getAdapter('siem');
    } catch (error) {
      expect(isIntegrationUnavailable(error)).toBe(true);
      if (isIntegrationUnavailable(error)) {
        expect(error.domain).toBe('siem');
        expect(error.missingRequirements.length).toBeGreaterThan(0);
      }
    }
  });

  it('throws IntegrationUnavailableError when no adapter is registered for a domain', () => {
    const registry = new IntegrationRegistry();
    expect(() => registry.getAdapter('siem')).toThrow(IntegrationUnavailableError);
  });

  it('honors explicit vendor preference', () => {
    const env: NodeJS.ProcessEnv = {
      ELASTIC_BASE_URL: 'https://elastic.example.com',
      ELASTIC_API_KEY: 'key',
      ELASTIC_INDEX: 'logs',
    };
    const registry = new IntegrationRegistry({
      credentials: { env },
      preference: { siem: 'elastic' },
    });
    registry.registerAll([
      {
        domain: 'siem',
        vendor: 'elastic',
        adapterId: 'elastic-search',
        requiredCredentials: [
          { envVar: 'ELASTIC_BASE_URL', configKey: 'baseUrl' },
          { envVar: 'ELASTIC_API_KEY', configKey: 'apiKey' },
          { envVar: 'ELASTIC_INDEX', configKey: 'index' },
        ],
        build: (resolver) => {
          const baseUrl = resolver.resolve('siem', 'elastic', 'ELASTIC_BASE_URL')?.value;
          return {
            metadata: {
              domain: 'siem',
              vendor: 'elastic',
              adapterId: 'elastic-search',
              displayName: 'elastic',
              description: '',
              capabilities: { searchEvents: true },
            },
            async health() {
              return { available: true, checkedAt: Date.now() };
            },
            async searchEvents() {
              return {
                value: [],
                provenance: {
                  domain: 'siem',
                  adapterId: 'elastic-search',
                  vendor: 'elastic',
                  capability: 'searchEvents',
                  method: 'api_query',
                  collectedAt: Date.now(),
                },
              };
            },
          };
        },
      },
    ]);
    const adapter = registry.getAdapter('siem', 'elastic');
    expect(adapter.metadata.vendor).toBe('elastic');
  });

  it('falls back to other vendors when the preferred vendor is unavailable', () => {
    const env: NodeJS.ProcessEnv = {};
    const registry = new IntegrationRegistry({
      credentials: { env },
      preference: { siem: 'splunk' },
    });
    registry.registerAll([
      {
        domain: 'siem',
        vendor: 'splunk',
        adapterId: 'splunk-rest',
        requiredCredentials: [{ envVar: 'SPLUNK_TOKEN' }],
        build: () => null,
      },
      {
        domain: 'siem',
        vendor: 'elastic',
        adapterId: 'elastic',
        requiredCredentials: [],
        build: () => ({
          metadata: {
            domain: 'siem',
            vendor: 'elastic',
            adapterId: 'elastic',
            displayName: 'elastic',
            description: '',
            capabilities: { searchEvents: true },
          },
          async health() {
            return { available: true, checkedAt: Date.now() };
          },
          async searchEvents() {
            return {
              value: [],
              provenance: {
                domain: 'siem',
                adapterId: 'elastic',
                vendor: 'elastic',
                capability: 'searchEvents',
                method: 'api_query',
                collectedAt: Date.now(),
              },
            };
          },
        }),
      },
    ]);
    const adapter = registry.getAdapter('siem');
    expect(adapter.metadata.vendor).toBe('elastic');
  });

  it('caches health check results', async () => {
    let calls = 0;
    const registry = new IntegrationRegistry({ healthCacheMs: 60_000 });
    registry.registerAll([
      {
        domain: 'siem',
        vendor: 'mock',
        adapterId: 'mock',
        requiredCredentials: [],
        build: () => ({
          metadata: {
            domain: 'siem',
            vendor: 'mock',
            adapterId: 'mock',
            displayName: 'mock',
            description: '',
            capabilities: { searchEvents: true },
          },
          async health() {
            calls += 1;
            return { available: true, checkedAt: Date.now() };
          },
          async searchEvents() {
            return {
              value: [],
              provenance: {
                domain: 'siem',
                adapterId: 'mock',
                vendor: 'mock',
                capability: 'searchEvents',
                method: 'api_query',
                collectedAt: Date.now(),
              },
            };
          },
        }),
      },
    ]);
    await registry.getHealthyAdapter('siem');
    await registry.getHealthyAdapter('siem');
    expect(calls).toBe(1);
    registry.invalidateHealth();
    await registry.getHealthyAdapter('siem');
    expect(calls).toBe(2);
  });
});
