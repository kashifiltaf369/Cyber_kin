/**
 * Scenario 07 — False positive investigation.
 *
 * A SOC alert fires on a Windows command-line that "looks like"
 * credential theft (it copies ntds.itu) but in context is actually a
 * legitimate, scheduled backup run by the Backup Service Account.
 * Investigators should follow the evidence, validate assumptions, and
 * close out the alert as benign.
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

export const falsePositiveScenario: SyntheticScenario = {
  id: 'false-positive',
  displayName: 'False positive (scheduled backup of ntds.itu)',
  shortDescription: 'SOC alert on ntds.itu copy turns out to be a scheduled backup run by svc-backup.',
  domain: 'identity / endpoint',
  difficulty: 'intro',
  build(): SyntheticDataset {
    const id = makeIdFactory('fp');
    const events: EventRecord[] = [
      {
        id: id(),
        timestamp: ts(0),
        source: 'synthetic-siem',
        severity: 'medium',
        message: 'Scheduled task "BackupDaily_AD" triggered on CYBER-WIN-DC01 running as svc-backup.',
        raw: { synthetic: true, eventCode: 'SCHEDULED_TASK' },
      },
      {
        id: id(),
        timestamp: ts(2),
        source: 'synthetic-siem',
        severity: 'high',
        message: 'File access: ntds.itu read by wbadmin.exe on CYBER-WIN-DC01.',
        raw: { synthetic: true, eventCode: 4663, image: 'wbadmin.exe' },
      },
      {
        id: id(),
        timestamp: ts(4),
        source: 'synthetic-siem',
        severity: 'high',
        message: 'Sysmon: ntds.itu copied to \\\\CYBER-WIN-FS01\\backup$\\ad-2025-09-15.bak.',
        raw: { synthetic: true, eventCode: 11 },
      },
      {
        id: id(),
        timestamp: ts(5),
        source: 'synthetic-siem',
        severity: 'medium',
        message: 'Change request CR-2025-0915-001 authorised the AD backup to FS01 by d.romero.',
        raw: { synthetic: true, change: 'CR-2025-0915-001' },
      },
    ];
    const processes: ProcessRecord[] = [
      {
        id: id(),
        host: SCENARIO_HOSTS.DC01.hostname,
        pid: 2014,
        name: 'wbadmin.exe',
        commandLine: 'wbadmin.exe start systemstatebackup -backupTarget:"\\\\CYBER-WIN-FS01\\backup$"',
        parentName: 'svchost.exe',
        parentPid: 1108,
        user: SCENARIO_USERS.svc.username,
        startTime: ts(1),
      },
    ];
    const networkConnections: NetworkConnectionRecord[] = [
      {
        id: id(),
        host: SCENARIO_HOSTS.DC01.hostname,
        processName: 'wbadmin.exe',
        pid: 2014,
        localAddress: SCENARIO_HOSTS.DC01.ip,
        remoteAddress: SCENARIO_HOSTS.FS01.ip,
        remotePort: 445,
        protocol: 'tcp',
        timestamp: ts(2),
      },
    ];
    const dnsQueries: DnsRecord[] = [];
    const identityActivity: IdentityActivityRecord[] = [
      {
        id: id(),
        actor: SCENARIO_USERS.svc.username,
        action: 'interactive-logon',
        target: SCENARIO_HOSTS.DC01.hostname,
        timestamp: SCENARIO_EPOCH_MS - 86_400_000,
        source: 'synthetic-identity',
        ipAddress: '10.10.10.5',
        result: 'success',
      },
      {
        id: id(),
        actor: SCENARIO_USERS.dave.username,
        action: 'change-approval',
        target: 'CR-2025-0915-001',
        timestamp: SCENARIO_EPOCH_MS - 3_600_000,
        source: 'synthetic-identity',
        ipAddress: '10.10.10.5',
        result: 'success',
      },
    ];
    const fileAnalysisReports: FileAnalysisReport[] = [];
    const indicatorLookups: IndicatorLookupResult[] = [
      {
        indicator: 'CR-2025-0915-001',
        indicatorType: 'unknown',
        verdict: 'benign',
        confidence: 95,
        categories: ['change-record'],
        sources: ['synthetic-feed'],
      },
    ];
    return {
      scenarioId: 'false-positive',
      objective: {
        title: '[SYNTHETIC DEMO] Investigate SOC alert on ntds.itu copy from CYBER-WIN-DC01',
        summary: 'ntds.itu was copied to FS01. Determine whether this is a real theft or an authorised backup.',
        initialPrompt:
          'A SOC alert fired because ntds.itu was copied from CYBER-WIN-DC01 to FS01. Investigate and decide.',
      },
      suspicion: {
        expectedFindings: [
          'Process was wbadmin.exe (not rundll32 or powershell)',
          'Initiated by the scheduled task BackupDaily_AD running as svc-backup',
          'Destination path is \\\\FS01\\backup$ — a known backup share',
          'Change request CR-2025-0915-001 authorised the activity',
        ],
        expectedHypotheses: [
          'The alert is a false positive — the activity matches the authorised AD backup runbook.',
        ],
        decoys: [
          'A separate, real suspicious activity is NOT present. This scenario should conclude BENIGN.',
        ],
      },
      hosts: [SCENARIO_HOSTS.DC01, SCENARIO_HOSTS.FS01],
      users: [SCENARIO_USERS.svc, SCENARIO_USERS.dave],
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