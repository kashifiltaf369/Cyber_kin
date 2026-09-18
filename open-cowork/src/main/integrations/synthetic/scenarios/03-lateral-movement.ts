/**
 * Scenario 03 — Lateral movement.
 *
 * From a compromised workstation (WS01), the attacker pivots using WMI and
 * SMB to the file server, then to the domain controller via WMI. They
 * enable WinRM and create a new local admin on FS01.
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

export const lateralMovementScenario: SyntheticScenario = {
  id: 'lateral-movement',
  displayName: 'Lateral movement (WMI / SMB / WinRM)',
  shortDescription: 'Compromised workstation pivots to FS01, then DC01 via WMI.',
  domain: 'endpoint / network / identity',
  difficulty: 'advanced',
  build(): SyntheticDataset {
    const id = makeIdFactory('lat');
    const t0 = ts(60);
    const events: EventRecord[] = [
      {
        id: id(),
        timestamp: t0,
        source: 'synthetic-siem',
        severity: 'medium',
        message: 'Sysmon: wmic.exe (PID 6104) spawned — command line contains /node:"CYBER-WIN-FS01".',
        raw: { synthetic: true, eventCode: 1, image: 'wmic.exe' },
      },
      {
        id: id(),
        timestamp: ts(61),
        source: 'synthetic-siem',
        severity: 'medium',
        message: 'Network logon from CYBER-WIN-WS01$ to CYBER-WIN-FS01 (Ntlm SPN: cifs/CYBER-WIN-FS01).',
        raw: { synthetic: true, eventCode: 4624, logonType: 3, targetServer: 'CYBER-WIN-FS01' },
      },
      {
        id: id(),
        timestamp: ts(62),
        source: 'synthetic-siem',
        severity: 'medium',
        message: 'WinRM enabled on CYBER-WIN-FS01 via wmic process call create.',
        raw: { synthetic: true, action: 'enable-winrm' },
      },
      {
        id: id(),
        timestamp: ts(70),
        source: 'synthetic-siem',
        severity: 'high',
        message: 'New local group addition: CYBER-WIN-FS01 — user "svc-backup" added to local Administrators.',
        raw: { synthetic: true, eventCode: 4732, group: 'Administrators' },
      },
      {
        id: id(),
        timestamp: ts(90),
        source: 'synthetic-siem',
        severity: 'high',
        message: 'WMI pivot from CYBER-WIN-FS01 to CYBER-WIN-DC01 — wmic /node:"CYBER-WIN-DC01".',
        raw: { synthetic: true, eventCode: 1, image: 'wmic.exe' },
      },
    ];
    const processes: ProcessRecord[] = [
      {
        id: id(),
        host: SCENARIO_HOSTS.WS01.hostname,
        pid: 6104,
        name: 'wmic.exe',
        commandLine: 'wmic /node:"CYBER-WIN-FS01" process call create "cmd.exe /c powershell -enc ..."',
        parentName: 'cmd.exe',
        parentPid: 5012,
        user: SCENARIO_USERS.alice.username,
        startTime: t0,
      },
      {
        id: id(),
        host: SCENARIO_HOSTS.FS01.hostname,
        pid: 8801,
        name: 'wmic.exe',
        commandLine: 'wmic /node:"CYBER-WIN-DC01" process call create "rundll32.exe diag.dll,Minidump"',
        parentName: 'powershell.exe',
        parentPid: 9210,
        user: SCENARIO_USERS.svc.username,
        startTime: ts(90),
      },
    ];
    const networkConnections: NetworkConnectionRecord[] = [
      {
        id: id(),
        host: SCENARIO_HOSTS.WS01.hostname,
        processName: 'wmic.exe',
        pid: 6104,
        localAddress: SCENARIO_HOSTS.WS01.ip,
        remoteAddress: SCENARIO_HOSTS.FS01.ip,
        remotePort: 135,
        protocol: 'tcp',
        timestamp: t0,
      },
      {
        id: id(),
        host: SCENARIO_HOSTS.WS01.hostname,
        processName: 'wmic.exe',
        pid: 6104,
        localAddress: SCENARIO_HOSTS.WS01.ip,
        remoteAddress: SCENARIO_HOSTS.FS01.ip,
        remotePort: 445,
        protocol: 'tcp',
        timestamp: ts(61),
      },
      {
        id: id(),
        host: SCENARIO_HOSTS.FS01.hostname,
        processName: 'wmic.exe',
        pid: 8801,
        localAddress: SCENARIO_HOSTS.FS01.ip,
        remoteAddress: SCENARIO_HOSTS.DC01.ip,
        remotePort: 135,
        protocol: 'tcp',
        timestamp: ts(90),
      },
    ];
    const dnsQueries: DnsRecord[] = [];
    const identityActivity: IdentityActivityRecord[] = [
      {
        id: id(),
        actor: SCENARIO_USERS.alice.username,
        action: 'network-logon',
        target: SCENARIO_HOSTS.FS01.hostname,
        timestamp: ts(61),
        source: 'synthetic-identity',
        ipAddress: SCENARIO_HOSTS.WS01.ip,
        result: 'success',
      },
      {
        id: id(),
        actor: SCENARIO_USERS.svc.username,
        action: 'group-membership-change',
        target: `${SCENARIO_HOSTS.FS01.hostname}\\Administrators`,
        timestamp: ts(70),
        source: 'synthetic-identity',
        ipAddress: SCENARIO_HOSTS.WS01.ip,
        result: 'success',
      },
      {
        id: id(),
        actor: SCENARIO_USERS.svc.username,
        action: 'network-logon',
        target: SCENARIO_HOSTS.DC01.hostname,
        timestamp: ts(91),
        source: 'synthetic-identity',
        ipAddress: SCENARIO_HOSTS.FS01.ip,
        result: 'success',
      },
    ];
    const fileAnalysisReports: FileAnalysisReport[] = [];
    const indicatorLookups: IndicatorLookupResult[] = [];
    return {
      scenarioId: 'lateral-movement',
      objective: {
        title: '[SYNTHETIC DEMO] Possible lateral movement from CYBER-WIN-WS01',
        summary: 'WMI pivots from a workstation to FS01 then DC01; svc-backup added to local admins.',
        initialPrompt:
          'Detections suggest an attacker is moving laterally from CYBER-WIN-WS01 to CYBER-WIN-FS01 and onwards to CYBER-WIN-DC01. Reconstruct the path and the compromised accounts.',
      },
      suspicion: {
        expectedFindings: [
          'wmic.exe originating from CYBER-WIN-WS01 contacting CYBER-WIN-FS01:135',
          'SMB session opened with the workstation host account',
          'svc-backup added to local Administrators on FS01',
          'Subsequent wmic pivot from FS01 to DC01',
        ],
        expectedHypotheses: [
          'The attacker pivoted via WMI (T1047), reusing harvested credentials to add a persistence admin (T1098).',
          'svc-backup is now compromised and used as a foothold toward the domain controller.',
        ],
        decoys: [
          'A scheduled task on FS01 named "BackupDaily" looks like legitimate backup automation.',
        ],
      },
      hosts: [
        SCENARIO_HOSTS.WS01,
        SCENARIO_HOSTS.FS01,
        SCENARIO_HOSTS.DC01,
      ],
      users: [SCENARIO_USERS.alice, SCENARIO_USERS.svc, SCENARIO_USERS.dave],
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