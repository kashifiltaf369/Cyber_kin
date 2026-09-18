/**
 * Scenario 04 — Suspicious login.
 *
 * A privileged user authenticates from two distant IPs within a few
 * minutes (impossible travel), one of which is a known residential
 * proxy range. MFA push requests fire but are denied repeatedly before
 * being accepted — possible MFA fatigue / push-bombing.
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

export const suspiciousLoginScenario: SyntheticScenario = {
  id: 'suspicious-login',
  displayName: 'Suspicious login (impossible travel + MFA fatigue)',
  shortDescription: 'Privileged account signs in from two distant IPs; MFA push-bombing precedes success.',
  domain: 'identity',
  difficulty: 'intermediate',
  build(): SyntheticDataset {
    const id = makeIdFactory('login');
    const events: EventRecord[] = [
      {
        id: id(),
        timestamp: ts(0),
        source: 'synthetic-siem',
        severity: 'medium',
        message: 'Repeated MFA push requests for d.romero (5 in 90 seconds). User denied 4, accepted 1.',
        raw: { synthetic: true, eventCode: 'MFA_PUSH', attempts: 5 },
      },
      {
        id: id(),
        timestamp: ts(1),
        source: 'synthetic-siem',
        severity: 'high',
        message: 'Sign-in success for d.romero from 203.0.113.7 (ASN 64512 residential proxy) — geolocation Bucharest, RO.',
        raw: { synthetic: true, eventCode: 'AAD_SignIn', geo: 'Bucharest' },
      },
      {
        id: id(),
        timestamp: ts(4),
        source: 'synthetic-siem',
        severity: 'high',
        message: 'Second sign-in success for d.romero from 198.18.0.4 (Tor exit node) — geolocation San Jose, US.',
        raw: { synthetic: true, eventCode: 'AAD_SignIn', geo: 'San Jose' },
      },
      {
        id: id(),
        timestamp: ts(7),
        source: 'synthetic-siem',
        severity: 'high',
        message: 'AADSTS conditional access: risky sign-in flagged, riskLevel=high.',
        raw: { synthetic: true, eventCode: 'AADSTS' },
      },
    ];
    const processes: ProcessRecord[] = [];
    const networkConnections: NetworkConnectionRecord[] = [];
    const dnsQueries: DnsRecord[] = [];
    const identityActivity: IdentityActivityRecord[] = [
      {
        id: id(),
        actor: SCENARIO_USERS.dave.username,
        action: 'mfa-push-denied',
        target: 'AzureAD',
        timestamp: ts(-1),
        source: 'synthetic-identity',
        ipAddress: '203.0.113.7',
        result: 'failure',
      },
      {
        id: id(),
        actor: SCENARIO_USERS.dave.username,
        action: 'mfa-push-denied',
        target: 'AzureAD',
        timestamp: ts(0),
        source: 'synthetic-identity',
        ipAddress: '203.0.113.7',
        result: 'failure',
      },
      {
        id: id(),
        actor: SCENARIO_USERS.dave.username,
        action: 'mfa-push-accepted',
        target: 'AzureAD',
        timestamp: ts(1),
        source: 'synthetic-identity',
        ipAddress: '203.0.113.7',
        result: 'success',
      },
      {
        id: id(),
        actor: SCENARIO_USERS.dave.username,
        action: 'interactive-logon',
        target: SCENARIO_HOSTS.DC01.hostname,
        timestamp: ts(4),
        source: 'synthetic-identity',
        ipAddress: '198.18.0.4',
        result: 'success',
      },
    ];
    const fileAnalysisReports: FileAnalysisReport[] = [];
    const indicatorLookups: IndicatorLookupResult[] = [
      {
        indicator: '203.0.113.7',
        indicatorType: 'ip',
        verdict: 'suspicious',
        confidence: 70,
        categories: ['residential-proxy'],
        sources: ['synthetic-feed'],
      },
      {
        indicator: '198.18.0.4',
        indicatorType: 'ip',
        verdict: 'malicious',
        confidence: 92,
        categories: ['tor-exit-node'],
        sources: ['synthetic-feed'],
      },
    ];
    return {
      scenarioId: 'suspicious-login',
      objective: {
        title: '[SYNTHETIC DEMO] Suspicious login for privileged user d.romero',
        summary: 'Privileged account authenticates from two distant IPs within minutes; MFA push-bombing.',
        initialPrompt:
          'Identity protection flagged risky sign-ins for d.romero from unfamiliar locations. Confirm whether this is a compromise and assess blast radius.',
      },
      suspicion: {
        expectedFindings: [
          '5 MFA push requests in 90 seconds, 4 denied then 1 accepted',
          'Successive sign-ins from 203.0.113.7 (Bucharest) and 198.18.0.4 (San Jose / Tor exit) within 3 minutes',
          'd.romero is privileged (it-ops admin)',
        ],
        expectedHypotheses: [
          'Adversary performed MFA fatigue / push bombing until user accepted (T1621).',
          'The d.romero account is compromised and pivoting from a Tor exit node.',
        ],
        decoys: [
          'Routine d.romero sign-in from 10.10.0.0/24 corporate VPN at 14:30 UTC the prior day.',
        ],
      },
      hosts: [SCENARIO_HOSTS.DC01, SCENARIO_HOSTS.FS01],
      users: [SCENARIO_USERS.dave],
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