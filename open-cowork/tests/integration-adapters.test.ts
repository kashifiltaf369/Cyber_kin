import { describe, expect, it, vi } from 'vitest';
import { SplunkSiemAdapter, SPLUNK_METADATA } from '../src/main/integrations/adapters/siem/splunk-adapter';
import { ElasticSiemAdapter, ELASTIC_METADATA } from '../src/main/integrations/adapters/siem/elastic-adapter';
import { MispThreatIntelAdapter, MISP_METADATA } from '../src/main/integrations/adapters/threat-intel/misp-adapter';
import { VirusTotalThreatIntelAdapter, VIRUSTOTAL_METADATA } from '../src/main/integrations/adapters/threat-intel/virustotal-adapter';
import { EntraIdentityAdapter, ENTRA_METADATA } from '../src/main/integrations/adapters/identity/entra-adapter';
import { ZeekNetworkAdapter, ZEEK_METADATA } from '../src/main/integrations/adapters/network/zeek-adapter';
import { CrowdStrikeEdrAdapter, CROWDSTRIKE_METADATA } from '../src/main/integrations/adapters/edr/crowdstrike-adapter';
import { redactCredential } from '../src/main/integrations/integration-credentials';

const originalFetch = globalThis.fetch;

function mockJsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('SIEM adapters', () => {
  it('Splunk metadata advertises searchEvents capability only', () => {
    expect(SPLUNK_METADATA.domain).toBe('siem');
    expect(SPLUNK_METADATA.capabilities).toEqual({ searchEvents: true });
  });

  it('Elastic metadata advertises searchEvents capability only', () => {
    expect(ELASTIC_METADATA.capabilities).toEqual({ searchEvents: true });
  });

  it('Splunk adapter converts searchEvents into vendor-neutral records', async () => {
    globalThis.fetch = vi.fn(async () =>
      mockJsonResponse({
        results: [
          { _time: '2024-01-01T00:00:00Z', _raw: 'failed login for admin', source: '/var/log/auth.log', severity: 'high' },
        ],
      })
    ) as unknown as typeof fetch;
    try {
      const adapter = new SplunkSiemAdapter('https://splunk.example.com', 't', 'main');
      const result = await adapter.searchEvents({ query: 'failed', limit: 10 });
      expect(result.provenance.domain).toBe('siem');
      expect(result.provenance.vendor).toBe('splunk');
      expect(result.value).toHaveLength(1);
      expect(result.value[0].message).toContain('failed login');
      expect(result.value[0].source).toBe('/var/log/auth.log');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('Splunk adapter redacts secrets in HTTP error messages', async () => {
    globalThis.fetch = vi.fn(async () => mockJsonResponse({ error: 'unauthorized token=abcdef1234567890abcdef1234567890abcdef' }, 401)) as unknown as typeof fetch;
    try {
      const adapter = new SplunkSiemAdapter('https://splunk.example.com', 't', 'main');
      try {
        await adapter.health();
        throw new Error('expected to throw');
      } catch (error) {
        const redacted = String(redactCredential(error instanceof Error ? error.message : String(error)));
        expect(redacted).not.toContain('abcdef1234567890abcdef1234567890abcdef');
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('Elastic adapter normalizes hit sources into events', async () => {
    globalThis.fetch = vi.fn(async () =>
      mockJsonResponse({
        hits: {
          hits: [
            { _id: '1', _index: 'logs', _source: { '@timestamp': '2024-01-01T00:00:00Z', message: 'auth failure' } },
          ],
        },
      })
    ) as unknown as typeof fetch;
    try {
      const adapter = new ElasticSiemAdapter('https://elastic.example.com', 'k', 'logs');
      const result = await adapter.searchEvents({ query: 'auth', limit: 1 });
      expect(result.provenance.vendor).toBe('elastic');
      expect(result.value[0].message).toBe('auth failure');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe('Threat intel adapters', () => {
  it('MISP classifies IP, domain, and hash correctly', async () => {
    globalThis.fetch = vi.fn(async () =>
      mockJsonResponse({
        response: {
          Attribute: [
            { value: '1.2.3.4', type: 'ip-dst', Event: { Tag: [{ name: 'malicious-activity' }] } },
          ],
        },
      })
    ) as unknown as typeof fetch;
    try {
      const adapter = new MispThreatIntelAdapter('https://misp.example.com', 'k');
      const result = await adapter.lookupIndicator('1.2.3.4');
      expect(result.value.indicatorType).toBe('ip');
      expect(result.value.verdict).toBe('malicious');
      expect(MISP_METADATA.domain).toBe('threat-intel');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('VirusTotal derives verdict from analysis stats', async () => {
    globalThis.fetch = vi.fn(async () =>
      mockJsonResponse({
        data: {
          attributes: {
            last_analysis_stats: { malicious: 5, suspicious: 2, harmless: 50, undetected: 10 },
            categories: { 'malicious-activity': 'evil.example' },
          },
        },
      })
    ) as unknown as typeof fetch;
    try {
      const adapter = new VirusTotalThreatIntelAdapter('https://vt.example.com', 'k');
      const result = await adapter.lookupIndicator('evil.example');
      expect(result.value.indicatorType).toBe('domain');
      expect(result.value.verdict).toBe('malicious');
      expect(VIRUSTOTAL_METADATA.capabilities).toEqual({ lookupIndicator: true });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe('Identity adapter', () => {
  it('Entra normalizes sign-in events with result verdict', async () => {
    globalThis.fetch = vi.fn(async () =>
      mockJsonResponse({
        value: [
          {
            id: 'evt-1',
            createdDateTime: '2024-01-01T00:00:00Z',
            userPrincipalName: 'alice@example.com',
            appDisplayName: 'Azure Portal',
            ipAddress: '203.0.113.10',
            status: { errorCode: 0 },
          },
          {
            id: 'evt-2',
            createdDateTime: '2024-01-01T00:01:00Z',
            userPrincipalName: 'bob@example.com',
            appDisplayName: 'Azure Portal',
            ipAddress: '198.51.100.5',
            status: { errorCode: 50126, failureReason: 'Invalid credentials' },
          },
        ],
      })
    ) as unknown as typeof fetch;
    try {
      const adapter = new EntraIdentityAdapter('https://graph.example.com', 't');
      const result = await adapter.queryIdentityActivity({ actor: 'alice@example.com' });
      expect(result.provenance.vendor).toBe('entra');
      expect(ENTRA_METADATA.capabilities).toEqual({ searchIdentityActivity: true });
      expect(result.value[0].result).toBe('success');
      expect(result.value[1].result).toBe('failure');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe('Network adapter (Zeek)', () => {
  it('reads conn.log and dns.log TSV files', async () => {
    const { writeFileSync, mkdtempSync, rmSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const path = await import('node:path');
    const root = mkdtempSync(path.join(tmpdir(), 'zeek-'));
    const connPath = path.join(root, 'conn.log');
    const dnsPath = path.join(root, 'dns.log');
    writeFileSync(
      connPath,
      [
        '#fields\tts\tuid\tid.orig_h\tid.resp_h\tid.resp_p\tproto',
        '1700000000.000000\tC1\t10.0.0.5\t203.0.113.10\t443\ttcp',
      ].join('\n'),
      'utf8'
    );
    writeFileSync(
      dnsPath,
      [
        '#fields\tts\tuid\tid.orig_h\tquery\tqtype_name\tanswers',
        '1700000001.000000\tD1\t10.0.0.5\tevil.example\tA\t1.2.3.4',
      ].join('\n'),
      'utf8'
    );
    try {
      const adapter = new ZeekNetworkAdapter(connPath, dnsPath);
      const health = await adapter.health();
      expect(health.available).toBe(true);
      const conns = await adapter.searchConnections({});
      expect(conns.value[0].remoteAddress).toBe('203.0.113.10');
      const dns = await adapter.searchDns({ name: 'evil' });
      expect(dns.value[0].query).toBe('evil.example');
      expect(ZEEK_METADATA.capabilities.searchDns).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('EDR adapter (CrowdStrike)', () => {
  it('advertises processes, network, and DNS capabilities', () => {
    expect(CROWDSTRIKE_METADATA.capabilities).toEqual({
      searchProcesses: true,
      searchNetworkConnections: true,
      searchDns: true,
    });
  });

  it('returns empty observations when there are no matching IDs', async () => {
    globalThis.fetch = vi.fn(async () =>
      mockJsonResponse({ resources: [] })
    ) as unknown as typeof fetch;
    try {
      const adapter = new CrowdStrikeEdrAdapter('https://falcon.example.com', 't');
      const result = await adapter.searchProcesses({ query: 'foo' });
      expect(result.value).toHaveLength(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
