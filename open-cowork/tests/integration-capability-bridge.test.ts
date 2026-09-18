import { describe, expect, it } from 'vitest';
import { IntegrationCapabilityBridge } from '../src/main/integrations/integration-capability-bridge';
import { CyberCapabilityRegistry } from '../src/main/cyber/cyber-capability-registry';
import {
  createDefaultIntegrationRegistry,
  IntegrationRegistry,
  IntegrationUnavailableError,
} from '../src/main/integrations';

function makeMockAdapterFactory(opts: {
  domain: 'siem' | 'edr' | 'network' | 'identity' | 'threat-intel' | 'file-analysis' | 'cloud-logs';
  vendor: string;
  adapterId: string;
  searchEventsResult?: { id: string; timestamp: number; source: string; message: string };
  lookupResult?: { verdict: string };
  requiresCreds?: Array<{ envVar: string }>;
}) {
  return {
    domain: opts.domain,
    vendor: opts.vendor,
    adapterId: opts.adapterId,
    requiredCredentials: opts.requiresCreds || [],
    build: () => ({
      metadata: {
        domain: opts.domain,
        vendor: opts.vendor,
        adapterId: opts.adapterId,
        displayName: `${opts.vendor}/${opts.adapterId}`,
        description: 'mock',
        capabilities: opts.domain === 'siem' ? { searchEvents: true } : opts.domain === 'threat-intel' ? { lookupIndicator: true } : {},
      },
      async health() {
        return { available: true, checkedAt: Date.now() };
      },
      async searchEvents() {
        return {
          value: opts.searchEventsResult ? [opts.searchEventsResult] : [],
          provenance: {
            domain: 'siem',
            adapterId: opts.adapterId,
            vendor: opts.vendor,
            capability: 'searchEvents',
            method: 'api_query',
            collectedAt: Date.now(),
          },
        };
      },
      async lookupIndicator(indicator: string) {
        return {
          value: {
            indicator,
            indicatorType: 'domain',
            verdict: opts.lookupResult?.verdict || 'malicious',
            confidence: 0.9,
            sources: [opts.vendor],
          },
          provenance: {
            domain: 'threat-intel',
            adapterId: opts.adapterId,
            vendor: opts.vendor,
            capability: 'lookupIndicator',
            method: 'api_query',
            collectedAt: Date.now(),
          },
        };
      },
    }),
  };
}

describe('IntegrationCapabilityBridge', () => {
  it('returns available domains based on registered factories', () => {
    const registry = new IntegrationRegistry();
    registry.registerAll([
      makeMockAdapterFactory({ domain: 'siem', vendor: 'mock-siem', adapterId: 'mock' }),
    ]);
    const bridge = new IntegrationCapabilityBridge(registry, new CyberCapabilityRegistry());
    expect(bridge.listAvailableDomains()).toContain('siem');
    expect(bridge.listAvailableDomains()).not.toContain('edr');
  });

  it('routes search_events through a SIEM adapter when available', async () => {
    const registry = new IntegrationRegistry();
    registry.registerAll([
      makeMockAdapterFactory({
        domain: 'siem',
        vendor: 'mock',
        adapterId: 'mock',
        searchEventsResult: {
          id: 'evt-1',
          timestamp: 1700000000000,
          source: 'mock-source',
          message: 'malicious activity detected',
        },
      }),
    ]);
    const bridge = new IntegrationCapabilityBridge(registry, new CyberCapabilityRegistry());
    const result = await bridge.runWithAdapterFallback('search_events', {
      query: 'malicious',
    }) as { matches: Array<{ line: string; provenance: { vendor: string } }>; provenance: { vendor: string } };
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].line).toContain('mock-source');
    expect(result.matches[0].line).toContain('malicious activity detected');
    expect(result.provenance.vendor).toBe('mock');
  });

  it('routes lookup_indicator through a threat intel adapter', async () => {
    const registry = new IntegrationRegistry();
    registry.registerAll([
      makeMockAdapterFactory({
        domain: 'threat-intel',
        vendor: 'mock-ti',
        adapterId: 'mock-ti',
        lookupResult: { verdict: 'malicious' },
      }),
    ]);
    const bridge = new IntegrationCapabilityBridge(registry, new CyberCapabilityRegistry());
    const result = await bridge.runWithAdapterFallback('lookup_indicator', {
      indicator: 'evil.example',
    }) as { verdict: string; provenance: { vendor: string } };
    expect(result.provenance.vendor).toBe('mock-ti');
  });

  it('falls back to local executor when no adapter is registered', async () => {
    const bridge = new IntegrationCapabilityBridge(new IntegrationRegistry(), new CyberCapabilityRegistry());
    const result = await bridge.runWithAdapterFallback('lookup_indicator', { indicator: 'evil.example' }) as { indicatorType: string };
    expect(result.indicatorType).toBe('domain');
  });

  it('falls back to local executor when adapter credentials are missing', async () => {
    const registry = new IntegrationRegistry();
    registry.registerAll([
      makeMockAdapterFactory({
        domain: 'siem',
        vendor: 'splunk',
        adapterId: 'splunk-rest',
        requiresCreds: [{ envVar: 'SPLUNK_TOKEN' }],
      }),
    ]);
    const unavailable: Array<{ domain: string; reason: string }> = [];
    const bridge = new IntegrationCapabilityBridge(registry, new CyberCapabilityRegistry(), {
      onUnavailable: (info) => unavailable.push(info),
    });
    await expect(
      bridge.runWithAdapterFallback('search_events', { sourcePath: '/tmp/__does_not_exist__.log', query: 'evil' })
    ).rejects.toThrow(/File not found/);
    expect(unavailable).toHaveLength(1);
    expect(unavailable[0].domain).toBe('siem');
    expect(unavailable[0].reason).toMatch(/Missing credential|Missing required credentials/);
  });
});
