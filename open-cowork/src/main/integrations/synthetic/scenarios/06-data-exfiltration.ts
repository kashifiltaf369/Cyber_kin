/**
 * Scenario 06 — Data exfiltration.
 *
 * After establishing a foothold (assumed), the attacker stages files into
 * a single archive on a file share and uploads ~6 GB over HTTPS to a
 * destination that was first resolved via DNS tunneling.
 */

import type {
  DnsRecord,
  EventRecord,
  IdentityActivityRecord,
  IndicatorLookupResult,
  NetworkConnectionRecord,
  ProcessRecord,
  FileAnalysisReport,
} from '../../integration-types';
import type { SyntheticDataset, SyntheticScenario } from '../scenario-types';
import { SCENARIO_HOSTS, SCENARIO_USERS, makeIdFactory, ts } from '../scenario-helpers';

export const dataExfiltrationScenario: SyntheticScenario = {
  id: 'data-exfiltration',
  displayName: 'Data exfiltration (large egress to unfamiliar IP)',
  shortDescription: '~6 GB uploaded to 198.51.100.99 after DNS lookups for a suspect tunnel domain.',
  domain: 'network / cloud-logs',
  difficulty: 'advanced',
  build(): SyntheticDataset {
    const id = makeIdFactory('exfil');
    const events: EventRecord[] = [
      {
        id: id(),
        timestamp: ts(0),
        source: 'synthetic-siem',
        severity: 'medium',
        message: 'High-entropy DNS queries for tunnel.example.io every 30s from CYBER-WIN-WS02.',
        raw: { synthetic: true, eventCode: 'DNS_TUNNEL_SUSPECTED' },
      },
      {
        id: id(),
        timestamp: ts(10),
        source: 'synthetic-siem',
        severity: 'medium',
        message: 'Archive created: \\\\CYBER-WIN-FS01\\share$\\staging\\q3-all.zip (6.2 GB).',
        raw: { synthetic: true, eventCode: 11 },
      },
      {
        id: id(),
        timestamp: ts(20),
        source: 'synthetic-siem',
        severity: 'high',
        message: 'Firewall: 5.97 GB outbound transfer from CYBER-WIN-FS01 to 198.51.100.99:443 over 42 minutes.',
        raw: { synthetic: true, eventCode: 'FW_EGRESS', bytes: 5526000000 },
      },
      {
        id: id(),
        timestamp: ts(60),
        source: 'synthetic-siem',
        severity: 'high',
        message: 'CASB alert: 6.1 GB uploaded to consumer cloud storage by svc-backup service principal.',
        raw: { synthetic: true, eventCode: 'CASB_UPLOAD' },
      },
    ];
    const processes: ProcessRecord[] = [];
    const networkConnections: NetworkConnectionRecord[] = [
      {
        id: id(),
        host: SCENARIO_HOSTS.FS01.hostname,
        processName: 'System',
        localAddress: SCENARIO_HOSTS.FS01.ip,
        remoteAddress: '198.51.100.99',
        remotePort: 443,
        protocol: 'tcp',
        timestamp: ts(20),
      },
    ];
    const dnsQueries: DnsRecord[] = [
      {
        id: id(),
        host: SCENARIO_HOSTS.WS02.hostname,
        timestamp: ts(0),
        query: 'tunnel.example.io',
        queryType: 'A',
        response: '198.51.100.99',
      },
      {
        id: id(),
        host: SCENARIO_HOSTS.WS02.hostname,
        timestamp: ts(1),
        query: 'aGVsbG8tYmFzZTY0LXN0YWdl.example.io',
        queryType: 'TXT',
        response: 'aGVsbG8=',
      },
    ];
    const identityActivity: IdentityActivityRecord[] = [
      {
        id: id(),
        actor: SCENARIO_USERS.svc.username,
        action: 'cloud-upload',
        target: 'consumer-cloud-storage',
        timestamp: ts(60),
        source: 'synthetic-identity',
        ipAddress: SCENARIO_HOSTS.FS01.ip,
        result: 'success',
      },
    ];
    const fileAnalysisReports: FileAnalysisReport[] = [];
    const indicatorLookups: IndicatorLookupResult[] = [
      {
        indicator: '198.51.100.99',
        indicatorType: 'ip',
        verdict: 'malicious',
        confidence: 93,
        categories: ['c2', 'exfiltration'],
        sources: ['synthetic-feed'],
      },
      {
        indicator: 'tunnel.example.io',
        indicatorType: 'domain',
        verdict: 'malicious',
        confidence: 89,
        categories: ['dns-tunnel'],
        sources: ['synthetic-feed'],
      },
    ];
    return {
      scenarioId: 'data-exfiltration',
      objective: {
        title: '[SYNTHETIC DEMO] Possible data exfiltration from CYBER-WIN-FS01',
        summary: '~6 GB transferred to 198.51.100.99 with DNS tunneling patterns preceding egress.',
        initialPrompt:
          'Network analytics flagged a large egress to an unfamiliar destination. Determine the source, the data, and the destination.',
      },
      suspicion: {
        expectedFindings: [
          'High-entropy DNS queries for tunnel.example.io',
          '5.97 GB firewall egress from FS01 to 198.51.100.99:443',
          'CASB alert for 6.1 GB uploaded by svc-backup service principal',
        ],
        expectedHypotheses: [
          'The attacker used DNS tunneling (T1071.004) to bootstrap C2 then transferred large staged archive over HTTPS (T1041 / T1567).',
          'svc-backup credentials are compromised and used as the egress channel.',
        ],
        decoys: [
          'Several Windows Update and AV signature downloads appear routine.',
        ],
      },
      hosts: [SCENARIO_HOSTS.WS02, SCENARIO_HOSTS.FS01],
      users: [SCENARIO_USERS.svc, SCENARIO_USERS.bob],
      events,
      processes,
      networkConnections,
      dnsQueries,
      identityActivity,
      fileAnalysisReports,
      indicatorLookups,
    };
  },
};