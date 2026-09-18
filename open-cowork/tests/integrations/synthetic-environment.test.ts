import { describe, expect, it, vi } from 'vitest';
import { SyntheticEnvironmentService } from '../src/main/integrations/synthetic/synthetic-environment-service';
import { SyntheticDatasetStore } from '../src/main/integrations/synthetic/synthetic-dataset';
import { SyntheticSiemAdapter } from '../src/main/integrations/synthetic/synthetic-siem-adapter';
import { SyntheticEdrAdapter } from '../src/main/integrations/synthetic/synthetic-edr-adapter';
import { SyntheticNetworkAdapter } from '../src/main/integrations/synthetic/synthetic-network-adapter';
import { SyntheticIdentityAdapter } from '../src/main/integrations/synthetic/synthetic-identity-adapter';
import { SyntheticThreatIntelAdapter } from '../src/main/integrations/synthetic/synthetic-threatintel-adapter';
import { SyntheticFileAnalysisAdapter } from '../src/main/integrations/synthetic/synthetic-file-analysis-adapter';
import { buildSyntheticFactories } from '../src/main/integrations/synthetic/synthetic-factories';
import { IntegrationRegistry } from '../src/main/integrations/integration-registry';
import { listSyntheticScenarios } from '../src/main/integrations/synthetic/scenarios';
import { SYNTHETIC_WATERMARK } from '../src/main/integrations/synthetic/scenario-types';
import { InvestigationService } from '../src/main/investigation/investigation-service';
import type {
  DatabaseInstance,
  InvestigationEventRow,
  InvestigationRow,
  InvestigationSessionLinkRow,
} from '../src/main/db/database';

function makeDb() {
  const investigations = new Map<string, InvestigationRow>();
  const events = new Map<string, InvestigationEventRow[]>();
  const links = new Map<string, InvestigationSessionLinkRow>();
  const db: DatabaseInstance = {
    raw: {} as never,
    investigations: {
      create: vi.fn((row: InvestigationRow) => investigations.set(row.id, { ...row })),
      update: vi.fn((id: string, updates: Partial<InvestigationRow>) => {
        const current = investigations.get(id);
        if (!current) return;
        investigations.set(id, { ...current, ...updates, updated_at: Date.now() });
      }),
      get: vi.fn((id: string) => investigations.get(id)),
      getAll: vi.fn(() => Array.from(investigations.values())),
      delete: vi.fn(),
    },
    investigationEvents: {
      create: vi.fn((row: InvestigationEventRow) => {
        const list = events.get(row.investigation_id) || [];
        list.push({ ...row });
        events.set(row.investigation_id, list);
      }),
      getByInvestigationId: vi.fn((id: string) => (events.get(id) || []).slice()),
      deleteByInvestigationId: vi.fn(),
    },
    investigationSessionLinks: {
      link: vi.fn((investigationId: string, sessionId: string, role: string) => {
        links.set(sessionId, { investigation_id: investigationId, session_id: sessionId, role, created_at: Date.now() });
      }),
      getInvestigationIdBySessionId: vi.fn((sessionId: string) => links.get(sessionId)?.investigation_id ?? null),
      getSessionLinksByInvestigationId: vi.fn((investigationId: string) =>
        Array.from(links.values()).filter((item) => item.investigation_id === investigationId)
      ),
      deleteBySessionId: vi.fn((sessionId: string) => {
        links.delete(sessionId);
      }),
    },
    sessions: {} as never,
    messages: {} as never,
    traceSteps: {} as never,
    scheduledTasks: {} as never,
    prepare: vi.fn() as never,
    exec: vi.fn(),
    pragma: vi.fn(),
    close: vi.fn(),
  };
  return { db, investigations, events, links };
}

function enableSyntheticEnv(): void {
  process.env.CYBER_SYNTHETIC_ENABLED = '1';
}

describe('SyntheticEnvironmentService', () => {
  it('lists the seven required scenarios', () => {
    const scenarios = listSyntheticScenarios();
    expect(scenarios).toHaveLength(7);
    const ids = scenarios.map((s) => s.id).sort();
    expect(ids).toEqual([
      'credential-theft',
      'data-exfiltration',
      'false-positive',
      'lateral-movement',
      'malicious-document',
      'suspicious-login',
      'suspicious-powershell',
    ]);
    for (const scenario of scenarios) {
      expect(scenario.displayName).toBeTruthy();
      expect(scenario.shortDescription).toBeTruthy();
      expect(scenario.difficulty).toMatch(/^(intro|intermediate|advanced)$/);
    }
  });

  it('refuses to load when synthetic environment is disabled', () => {
    delete process.env.CYBER_SYNTHETIC_ENABLED;
    const { db } = makeDb();
    const investigationService = new InvestigationService(db);
    const service = new SyntheticEnvironmentService(investigationService, { enabled: false });
    expect(service.isAvailable()).toBe(false);
    expect(() => service.load('suspicious-powershell')).toThrow(SYNTHETIC_WATERMARK);
  });

  it('loads a scenario, returns a populated dataset, and seeds an investigation with watermark', () => {
    enableSyntheticEnv();
    const { db } = makeDb();
    const investigationService = new InvestigationService(db);
    const service = new SyntheticEnvironmentService(investigationService, { enabled: true });

    const dataset = service.load('suspicious-powershell');
    expect(dataset.events.length).toBeGreaterThan(0);
    expect(dataset.processes.length).toBeGreaterThan(0);
    expect(dataset.networkConnections.length).toBeGreaterThan(0);
    expect(dataset.indicatorLookups.length).toBeGreaterThan(0);
    expect(dataset.objective.title.startsWith('[SYNTHETIC DEMO]')).toBe(true);

    const investigation = service.seedInvestigation('suspicious-powershell');
    expect(investigation.title.startsWith('[SYNTHETIC DEMO]')).toBe(true);
    expect(investigation.objective).toBe(dataset.objective.initialPrompt);

    const events = (db.investigationEvents.getByInvestigationId as ReturnType<typeof vi.fn>).mock.results
      .map((r) => r.value)
      .flat()
      .filter((e) => e && e.investigation_id === investigation.id) as InvestigationEventRow[];
    const notice = events.find((e) => e.summary.includes(SYNTHETIC_WATERMARK));
    expect(notice).toBeDefined();
  });

  it('reset() clears the active dataset', () => {
    enableSyntheticEnv();
    const service = new SyntheticEnvironmentService(undefined, { enabled: true });
    service.load('credential-theft');
    expect(service.status().loaded).toBe(true);
    service.reset();
    expect(service.status().loaded).toBe(false);
  });

  it('refuses to seed without an InvestigationService', () => {
    enableSyntheticEnv();
    const service = new SyntheticEnvironmentService(undefined, { enabled: true });
    service.load('credential-theft');
    expect(() => service.seedInvestigation('credential-theft')).toThrow(/InvestigationService/);
  });
});

describe('Synthetic adapters return watermarked observations', () => {
  it('every adapter tags records with synthetic provenance and adapterId', async () => {
    enableSyntheticEnv();
    const service = new SyntheticEnvironmentService(undefined, { enabled: true });
    service.load('lateral-movement');

    const siem = new SyntheticSiemAdapter(service.store);
    const edr = new SyntheticEdrAdapter(service.store);
    const net = new SyntheticNetworkAdapter(service.store);
    const identity = new SyntheticIdentityAdapter(service.store);
    const threat = new SyntheticThreatIntelAdapter(service.store);
    const files = new SyntheticFileAnalysisAdapter(service.store);

    const events = await siem.searchEvents({});
    expect(events.provenance.adapterId).toBe('synthetic-siem');
    expect(events.provenance.vendor).toBe('synthetic');
    expect(events.provenance.method).toBe('file_import');
    expect(events.value.every((e) => (e.raw as Record<string, unknown>)?.synthetic === true)).toBe(true);

    const procs = await edr.searchProcesses({});
    expect(procs.provenance.adapterId).toBe('synthetic-edr');
    expect(procs.value.length).toBeGreaterThan(0);

    const conns = await edr.searchNetworkConnections({});
    expect(conns.provenance.adapterId).toBe('synthetic-edr');
    expect(conns.value.every((c) => (c.raw as Record<string, unknown>)?.synthetic === true)).toBe(true);

    const dns = await net.searchDns({});
    expect(dns.provenance.adapterId).toBe('synthetic-network');

    const auth = await identity.queryIdentityActivity({});
    expect(auth.provenance.adapterId).toBe('synthetic-identity');

    const lookup = await threat.lookupIndicator('198.51.100.99');
    expect(lookup.provenance.adapterId).toBe('synthetic-threatintel');
    expect(lookup.value.verdict).toBeTruthy();

    const report = await files.submitFileForAnalysis({
      fileName: 'evil.docm',
      contentRef: 'memory:test',
    });
    expect(report.provenance.adapterId).toBe('synthetic-file-analysis');
    expect(report.value.submissionId).toBeTruthy();
  });

  it('health() reports unavailable when no scenario is loaded', async () => {
    enableSyntheticEnv();
    const store = new SyntheticDatasetStore();
    const siem = new SyntheticSiemAdapter(store);
    const health = await siem.health();
    expect(health.available).toBe(false);
    expect(health.reason).toContain('No synthetic scenario loaded');
  });

  it('searchEvents throws IntegrationUnavailableError when not loaded', async () => {
    enableSyntheticEnv();
    const store = new SyntheticDatasetStore();
    const siem = new SyntheticSiemAdapter(store);
    await expect(siem.searchEvents({})).rejects.toThrow(/No synthetic scenario loaded/);
  });
});

describe('Synthetic factories and registry', () => {
  it('registers factories for every required integration domain', () => {
    enableSyntheticEnv();
    const store = new SyntheticDatasetStore();
    const factories = buildSyntheticFactories(store);
    const domains = factories.map((f) => f.domain).sort();
    expect(domains).toEqual([
      'edr',
      'file-analysis',
      'identity',
      'network',
      'siem',
      'threat-intel',
    ]);
  });

  it('returns null adapters when CYBER_SYNTHETIC_ENABLED is not set', () => {
    delete process.env.CYBER_SYNTHETIC_ENABLED;
    const store = new SyntheticDatasetStore();
    const factories = buildSyntheticFactories(store);
    for (const factory of factories) {
      const adapter = factory.build({} as never);
      expect(adapter).toBeNull();
    }
  });

  it('IntegrationRegistry.getAdapter resolves synthetic adapters by domain when enabled', () => {
    enableSyntheticEnv();
    const store = new SyntheticDatasetStore();
    const registry = new IntegrationRegistry({
      preference: {
        siem: 'synthetic',
        edr: 'synthetic',
        network: 'synthetic',
        identity: 'synthetic',
        'threat-intel': 'synthetic',
        'file-analysis': 'synthetic',
      },
    });
    registry.registerAll(buildSyntheticFactories(store));

    const siem = registry.getAdapter('siem');
    expect(siem.metadata.adapterId).toBe('synthetic-siem');
    const edr = registry.getAdapter('edr');
    expect(edr.metadata.adapterId).toBe('synthetic-edr');
    const identity = registry.getAdapter('identity');
    expect(identity.metadata.adapterId).toBe('synthetic-identity');
  });
});

describe('Scenario dataset contents exercise the investigation architecture', () => {
  it('lateral-movement dataset includes process, network, and identity records an investigator can correlate', () => {
    enableSyntheticEnv();
    const service = new SyntheticEnvironmentService(undefined, { enabled: true });
    const dataset = service.load('lateral-movement');

    expect(dataset.processes.length).toBeGreaterThan(0);
    expect(dataset.networkConnections.length).toBeGreaterThan(0);
    expect(dataset.identityActivity.length).toBeGreaterThan(0);
    const wmicPids = new Set(dataset.processes.filter((p) => p.name === 'wmic.exe').map((p) => p.pid));
    const matchingConn = dataset.networkConnections.find((c) => wmicPids.has(c.pid));
    expect(matchingConn).toBeDefined();
  });

  it('false-positive scenario has scheduled-task + change-request evidence supporting a benign conclusion', () => {
    enableSyntheticEnv();
    const service = new SyntheticEnvironmentService(undefined, { enabled: true });
    const dataset = service.load('false-positive');

    expect(dataset.processes.some((p) => p.name === 'wbadmin.exe')).toBe(true);
    const changeApproval = dataset.identityActivity.find((a) => a.action === 'change-approval');
    expect(changeApproval).toBeDefined();
  });
});