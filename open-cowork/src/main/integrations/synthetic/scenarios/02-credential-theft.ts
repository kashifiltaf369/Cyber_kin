/**
 * Scenario 02 — Credential theft (LSASS dump).
 *
 * An attacker who already has code execution on a workstation opens a
 * handle to lsass.exe with PROCESS_VM_READ access and writes a MiniDumper
 * style dump to disk. Then they ZIP it (renamed) and stage it for
 * exfiltration.
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

export const credentialTheftScenario: SyntheticScenario = {
  id: 'credential-theft',
  displayName: 'Credential theft (LSASS dump)',
  shortDescription: 'rundll32 loads a MiniDumper against lsass.exe; dump is renamed and zipped.',
  domain: 'endpoint / identity',
  difficulty: 'intermediate',
  build(): SyntheticDataset {
    const id = makeIdFactory('cred');
    const events: EventRecord[] = [
      {
        id: id(),
        timestamp: ts(10),
        source: 'synthetic-siem',
        severity: 'medium',
        message: 'Sysmon: process access — rundll32.exe (PID 5512) opened lsass.exe (PID 720) with PROCESS_VM_READ.',
        raw: { synthetic: true, eventCode: 10, grantedAccess: '0x1010' },
      },
      {
        id: id(),
        timestamp: ts(12),
        source: 'synthetic-siem',
        severity: 'high',
        message: 'File created: C:\\Users\\b.lin\\AppData\\Local\\Temp\\diag.bin (12 MB).',
        raw: { synthetic: true, eventCode: 11, targetFilename: 'C:\\Users\\b.lin\\AppData\\Local\\Temp\\diag.bin' },
      },
      {
        id: id(),
        timestamp: ts(13),
        source: 'synthetic-siem',
        severity: 'high',
        message: 'Sysmon: image load of mimidrv.sys (unsigned driver) by rundll32.exe.',
        raw: { synthetic: true, eventCode: 6, signed: false },
      },
      {
        id: id(),
        timestamp: ts(14),
        source: 'synthetic-siem',
        severity: 'high',
        message: 'Sysmon: diag.bin renamed to report.zip.',
        raw: { synthetic: true, eventCode: 11, oldName: 'diag.bin', newName: 'report.zip' },
      },
    ];
    const processes: ProcessRecord[] = [
      {
        id: id(),
        host: SCENARIO_HOSTS.WS02.hostname,
        pid: 5512,
        name: 'rundll32.exe',
        commandLine: 'rundll32.exe C:\\Users\\b.lin\\AppData\\Roaming\\diag.dll,Minidump',
        parentName: 'cmd.exe',
        parentPid: 4402,
        user: SCENARIO_USERS.bob.username,
        startTime: ts(9),
      },
      {
        id: id(),
        host: SCENARIO_HOSTS.WS02.hostname,
        pid: 720,
        name: 'lsass.exe',
        commandLine: 'C:\\Windows\\System32\\lsass.exe',
        parentName: 'wininit.exe',
        parentPid: 612,
        startTime: SCENARIO_EPOCH_MS,
      },
    ];
    const networkConnections: NetworkConnectionRecord[] = [];
    const dnsQueries: DnsRecord[] = [];
    const identityActivity: IdentityActivityRecord[] = [
      {
        id: id(),
        actor: SCENARIO_USERS.bob.username,
        action: 'interactive-logon',
        target: SCENARIO_HOSTS.WS02.hostname,
        timestamp: SCENARIO_EPOCH_MS,
        source: 'synthetic-identity',
        ipAddress: '10.10.20.32',
        result: 'success',
      },
    ];
    const fileAnalysisReports: FileAnalysisReport[] = [
      {
        submissionId: 'fa-cred-001',
        status: 'complete',
        verdict: 'malicious',
        score: 95,
        engines: [
          { name: 'CrowdStrike Sandboxing', verdict: 'malicious' },
          { name: 'Joe Sandbox', verdict: 'malicious' },
        ],
        completedAt: ts(20),
      },
    ];
    const indicatorLookups: IndicatorLookupResult[] = [
      {
        indicator: 'C:\\Users\\b.lin\\AppData\\Roaming\\diag.dll',
        indicatorType: 'url',
        verdict: 'malicious',
        confidence: 90,
        categories: ['credential-dumper'],
        sources: ['synthetic-feed'],
      },
      {
        indicator: 'mimidrv',
        indicatorType: 'unknown',
        verdict: 'malicious',
        confidence: 80,
        categories: ['lol-driver'],
        sources: ['synthetic-feed'],
      },
    ];
    return {
      scenarioId: 'credential-theft',
      objective: {
        title: '[SYNTHETIC DEMO] Possible LSASS credential theft on CYBER-WIN-WS02',
        summary: 'rundll32 with MiniDumper arg opened lsass.exe for reading; output renamed to .zip.',
        initialPrompt:
          'The EDR flagged suspicious access to lsass.exe on CYBER-WIN-WS02. Investigate what happened, what was extracted, and which credentials are at risk.',
      },
      suspicion: {
        expectedFindings: [
          'rundll32.exe (parent: cmd.exe) accessed lsass.exe with PROCESS_VM_READ',
          'A 12 MB file named diag.bin appeared in Temp, then was renamed to report.zip',
          'An unsigned driver mimidrv.sys was loaded by rundll32.exe',
        ],
        expectedHypotheses: [
          'The attacker used a MiniDumper-style technique to dump LSASS and harvest credentials (T1003.001).',
          'The dump is staged for exfiltration; expect follow-on network activity.',
        ],
        decoys: [
          'Periodic Windows Defender quick scan events look routine.',
        ],
      },
      hosts: [SCENARIO_HOSTS.WS02, SCENARIO_HOSTS.DC01],
      users: [SCENARIO_USERS.bob, SCENARIO_USERS.dave],
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