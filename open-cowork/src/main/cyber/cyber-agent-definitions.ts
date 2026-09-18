import type { CyberCapabilityName } from './cyber-capability-registry';
import type { InvestigationAgentRole } from '../investigation/parallel-investigation-engine';
import type { InvestigationFindingType } from '../../shared/cyber/investigation-types';

export type EvidenceClassification = 'OBSERVED' | 'INFERRED' | 'UNKNOWN';

export const EVIDENCE_CLASSIFICATIONS: readonly EvidenceClassification[] = [
  'OBSERVED',
  'INFERRED',
  'UNKNOWN',
] as const;

export const ALLOWED_FINDING_TYPES: readonly InvestigationFindingType[] = [
  'OBSERVATION',
  'INFERENCE',
  'HYPOTHESIS',
  'CONCLUSION',
] as const;

export interface AgentCapabilityAllowList {
  capabilities: CyberCapabilityName[];
  toolCategories: ReadonlyArray<
    | 'filesystem:read'
    | 'analysis:safe-only'
    | 'investigation:read'
    | 'investigation:write_evidence'
    | 'investigation:write_hypothesis'
    | 'investigation:write_note'
| 'investigation:write_question'
    | 'human:ask'
  >;
  forbidden: ReadonlyArray<
    | 'destructive_action'
    | 'remote_execution'
    | 'credential_use'
    | 'process_injection'
    | 'network_write'
    | 'autonomous_remediation'
    | 'external_enrichment'
    | 'cross_scope_attribution'
  >;
}

export interface AgentInputSchemaField {
  path: string;
  type: 'string' | 'number' | 'boolean' | 'string[]' | 'object';
  required: boolean;
  description: string;
}

export interface AgentOutputSchemaField {
  path: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'object[]' | 'string[]';
  required: boolean;
  classification: EvidenceClassification;
  description: string;
}

export interface AgentFailureBehavior {
  transientRetry: boolean;
  maxRetries: number;
  onExhausted: 'fail_task_and_record_open_question' | 'block_synthesis_and_report';
  onInvalidStructuredOutput: 'reject_and_retry' | 'reject_and_record_note';
  onAmbiguity: 'emit_unknown_classification_only' | 'request_human_clarification';
}

export interface AgentConfidenceBehavior {
  defaultForObservations: number;
  defaultForInferences: number;
  defaultForUnknowns: number;
  minimumForConclusionClaim: number;
  downgradesOnUnattestedClaim: boolean;
  neverAbove: number;
}

export interface AgentCompletionCriteria {
  minimumEvidenceItems: number;
  minimumDistinctProvenanceSources: number;
  mustAcknowledgeUnknowns: boolean;
  mustCiteProvenancePerEvidence: boolean;
  mustReferenceHumanConstraints: boolean;
  outputShapeValid: boolean;
}

export interface AgentEvidenceResponsibility {
  classification: EvidenceClassification;
  mustInclude: ReadonlyArray<'source_path' | 'line_number' | 'excerpt' | 'capability_used' | 'timestamp' | 'entity_ids'>;
  mayNotInclude: ReadonlyArray<'fabricated_ioc' | 'unsupported_attribution' | 'phantom_process' | 'phantom_ip' | 'phantom_user'>;
}

export interface CyberAgentDefinition {
  role: InvestigationAgentRole;
  displayName: string;
  shortLabel: string;
  capabilityScope: string;
  objective: string;
  allowedTools: AgentCapabilityAllowList;
  inputSchema: AgentInputSchemaField[];
  outputSchema: AgentOutputSchemaField[];
  evidenceResponsibility: AgentEvidenceResponsibility;
  confidenceBehavior: AgentConfidenceBehavior;
  failureBehavior: AgentFailureBehavior;
  completionCriteria: AgentCompletionCriteria;
  systemPrompt: string;
  negativePrompt: string;
  allowedFindingTypes: readonly InvestigationFindingType[];
  forbiddenFindingTypes: readonly InvestigationFindingType[];
}

void 0;

function scopeFields(
  ...fields: Array<Omit<AgentInputSchemaField, 'required'> & { required?: boolean }>
): AgentInputSchemaField[] {
  return fields.map((field) => ({ required: field.required ?? true, ...field }));
}

function outputSpec(
  ...fields: Array<Omit<AgentOutputSchemaField, 'required' | 'classification'> & {
    classification?: EvidenceClassification;
    required?: boolean;
  }>
): AgentOutputSchemaField[] {
  return fields.map((field) => ({
    required: field.required ?? true,
    classification: field.classification ?? 'OBSERVED',
    ...field,
  }));
}

export const CYBER_AGENT_DEFINITIONS: Record<InvestigationAgentRole, CyberAgentDefinition> = {
  'Endpoint Investigator': {
    role: 'Endpoint Investigator',
    displayName: 'Endpoint Investigator',
    shortLabel: 'Endpoint',
    capabilityScope:
      'Process execution, file artifacts, registry/persistence, host-level telemetry on the affected system. No network attribution, no identity attribution, no external enrichment.',
    objective:
      'Collect host-side evidence (process trees, binaries, scheduled tasks, registry keys, file artifacts) and describe only what is present on disk or in process listings.',
    allowedTools: {
      capabilities: ['search_processes', 'inspect_file', 'calculate_hash', 'query_local_logs'],
      toolCategories: ['filesystem:read', 'analysis:safe-only', 'investigation:read', 'investigation:write_evidence', 'investigation:write_note', 'investigation:write_question'],
      forbidden: ['destructive_action', 'remote_execution', 'credential_use', 'autonomous_remediation', ],
    },
    inputSchema: scopeFields(
      { path: 'investigation.objective', type: 'string', description: 'Investigation objective.' },
      { path: 'host.entityId', type: 'string', description: 'Host entity under analysis.' },
      { path: 'host.timeWindow.start', type: 'number', description: 'Window start epoch ms.', required: false },
      { path: 'host.timeWindow.end', type: 'number', description: 'Window end epoch ms.', required: false },
      { path: 'host.knownLegitimateBehavior', type: 'string[]', description: 'Human-supplied legitimate behavior to avoid misclassifying.', required: false }
    ),
    outputSchema: outputSpec(
      { path: 'summary', type: 'string', classification: 'OBSERVED', description: 'Plain-language summary grounded only in host evidence seen.' },
      { path: 'evidence[].process', type: 'object', classification: 'OBSERVED', description: 'Process snapshot rows (pid, name, path, parent).', required: false },
      { path: 'evidence[].file', type: 'object', classification: 'OBSERVED', description: 'File inspection results with hash + metadata.', required: false },
      { path: 'evidence[].persistence', type: 'object', classification: 'OBSERVED', description: 'Persistence artifacts (registry, scheduled tasks, services).', required: false },
      { path: 'inferences', type: 'object[]', classification: 'INFERRED', description: 'Analyst inferences that combine multiple host observations.', required: false },
      { path: 'unknowns', type: 'object[]', classification: 'UNKNOWN', description: 'Questions that host evidence alone cannot resolve.', required: false }
    ),
    evidenceResponsibility: {
      classification: 'OBSERVED',
      mustInclude: ['source_path', 'excerpt', 'capability_used', 'timestamp'],
      mayNotInclude: ['fabricated_ioc', 'phantom_process', 'phantom_ip', 'unsupported_attribution'],
    },
    confidenceBehavior: {
      defaultForObservations: 0.8,
      defaultForInferences: 0.55,
      defaultForUnknowns: 0,
      minimumForConclusionClaim: 0.85,
      downgradesOnUnattestedClaim: true,
      neverAbove: 0.85,
    },
    failureBehavior: {
      transientRetry: true,
      maxRetries: 1,
      onExhausted: 'fail_task_and_record_open_question',
      onInvalidStructuredOutput: 'reject_and_retry',
      onAmbiguity: 'emit_unknown_classification_only',
    },
    completionCriteria: {
      minimumEvidenceItems: 1,
      minimumDistinctProvenanceSources: 1,
      mustAcknowledgeUnknowns: true,
      mustCiteProvenancePerEvidence: true,
      mustReferenceHumanConstraints: true,
      outputShapeValid: true,
    },
    allowedFindingTypes: ['OBSERVATION', 'INFERENCE'],
    forbiddenFindingTypes: ['CONCLUSION'],
    systemPrompt:
      'You are the Endpoint Investigator. You only answer host-side questions (processes, files, persistence). ' +
      'Every evidence item must include provenance. If something is not directly visible, mark it INFERRED or UNKNOWN. ' +
      'Do not invent IPs, domains, users or attribution. Never conclude a compromise from one process alone.',
    negativePrompt:
      'Do not make network claims, identity claims, or threat-intel attributions. ' +
      'Do not fabricate timestamps, hashes, or registry keys. Do not recommend remediation.',
  },

  'Network Investigator': {
    role: 'Network Investigator',
    displayName: 'Network Investigator',
    shortLabel: 'Network',
    capabilityScope:
      'Connections, DNS resolutions, domains, IPs, packet captures, lateral movement patterns. No host execution claims, no identity claims, no external enrichment.',
    objective:
      'Collect and correlate network-side evidence (DNS, flows, connection metadata, PCAP excerpts) and describe only the communications actually observed.',
    allowedTools: {
      capabilities: ['search_network_connections', 'search_dns', 'analyze_pcap'],
      toolCategories: ['filesystem:read', 'analysis:safe-only', 'investigation:read', 'investigation:write_evidence', 'investigation:write_note', 'investigation:write_question'],
      forbidden: ['destructive_action', 'remote_execution', 'credential_use', 'autonomous_remediation', ],
    },
    inputSchema: scopeFields(
      { path: 'investigation.objective', type: 'string', description: 'Investigation objective.' },
      { path: 'network.timeWindow.start', type: 'number', description: 'Window start epoch ms.', required: false },
      { path: 'network.timeWindow.end', type: 'number', description: 'Window end epoch ms.', required: false },
      { path: 'network.focusedEntities', type: 'string[]', description: 'Hosts/users/accounts whose traffic is in scope.', required: false }
    ),
    outputSchema: outputSpec(
      { path: 'summary', type: 'string', classification: 'OBSERVED', description: 'Plain-language summary grounded only in network evidence seen.' },
      { path: 'evidence[].connection', type: 'object', classification: 'OBSERVED', description: 'Connection / flow rows.', required: false },
      { path: 'evidence[].dns', type: 'object', classification: 'OBSERVED', description: 'DNS resolution rows.', required: false },
      { path: 'evidence[].pcap', type: 'object', classification: 'OBSERVED', description: 'PCAP packet metadata excerpts.', required: false },
      { path: 'inferences', type: 'object[]', classification: 'INFERRED', description: 'Analyst inferences about beaconing, lateral movement, exfil.', required: false },
      { path: 'unknowns', type: 'object[]', classification: 'UNKNOWN', description: 'Questions network evidence alone cannot resolve.', required: false }
    ),
    evidenceResponsibility: {
      classification: 'OBSERVED',
      mustInclude: ['source_path', 'excerpt', 'capability_used', 'timestamp'],
      mayNotInclude: ['fabricated_ioc', 'phantom_ip', 'unsupported_attribution'],
    },
    confidenceBehavior: {
      defaultForObservations: 0.8,
      defaultForInferences: 0.5,
      defaultForUnknowns: 0,
      minimumForConclusionClaim: 0.9,
      downgradesOnUnattestedClaim: true,
      neverAbove: 0.8,
    },
    failureBehavior: {
      transientRetry: true,
      maxRetries: 1,
      onExhausted: 'fail_task_and_record_open_question',
      onInvalidStructuredOutput: 'reject_and_retry',
      onAmbiguity: 'emit_unknown_classification_only',
    },
    completionCriteria: {
      minimumEvidenceItems: 1,
      minimumDistinctProvenanceSources: 1,
      mustAcknowledgeUnknowns: true,
      mustCiteProvenancePerEvidence: true,
      mustReferenceHumanConstraints: true,
      outputShapeValid: true,
    },
    allowedFindingTypes: ['OBSERVATION', 'INFERENCE'],
    forbiddenFindingTypes: ['CONCLUSION'],
    systemPrompt:
      'You are the Network Investigator. You only answer communications questions (DNS, IPs, domains, connections, packets). ' +
      'Every evidence item must include provenance (source path + excerpt). If something cannot be tied back to a packet or log row, mark it INFERRED or UNKNOWN. ' +
      'Beaconing, exfiltration, and lateral movement are inferences, not observations.',
    negativePrompt:
      'Do not invent IPs, domains, or connection timing. Do not make endpoint or identity claims. Do not perform vendor lookups.',
  },

  'Identity Investigator': {
    role: 'Identity Investigator',
    displayName: 'Identity Investigator',
    shortLabel: 'Identity',
    capabilityScope:
      'Authentication events, account activity, MFA, sign-in flows, privilege grants, role assignments. No host execution claims, no packet claims, no external enrichment.',
    objective:
      'Collect identity-plane evidence (sign-ins, MFA prompts, role grants, token issuance) and describe only the auth behavior actually observed.',
    allowedTools: {
      capabilities: ['search_identity_activity', 'search_events'],
      toolCategories: ['filesystem:read', 'analysis:safe-only', 'investigation:read', 'investigation:write_evidence', 'investigation:write_note', 'investigation:write_question'],
      forbidden: ['destructive_action', 'remote_execution', 'credential_use', 'autonomous_remediation', ],
    },
    inputSchema: scopeFields(
      { path: 'investigation.objective', type: 'string', description: 'Investigation objective.' },
      { path: 'identity.userIds', type: 'string[]', description: 'Users/accounts under analysis.', required: false },
      { path: 'identity.timeWindow.start', type: 'number', description: 'Window start epoch ms.', required: false },
      { path: 'identity.timeWindow.end', type: 'number', description: 'Window end epoch ms.', required: false }
    ),
    outputSchema: outputSpec(
      { path: 'summary', type: 'string', classification: 'OBSERVED', description: 'Plain-language summary grounded only in identity evidence seen.' },
      { path: 'evidence[].signin', type: 'object', classification: 'OBSERVED', description: 'Sign-in event rows.', required: false },
      { path: 'evidence[].mfa', type: 'object', classification: 'OBSERVED', description: 'MFA challenge / result rows.', required: false },
      { path: 'evidence[].privilege', type: 'object', classification: 'OBSERVED', description: 'Role / grant rows.', required: false },
      { path: 'inferences', type: 'object[]', classification: 'INFERRED', description: 'Analyst inferences about credential abuse or impossible travel.', required: false },
      { path: 'unknowns', type: 'object[]', classification: 'UNKNOWN', description: 'Questions identity evidence alone cannot resolve.', required: false }
    ),
    evidenceResponsibility: {
      classification: 'OBSERVED',
      mustInclude: ['source_path', 'excerpt', 'capability_used', 'timestamp', 'entity_ids'],
      mayNotInclude: ['phantom_user', 'fabricated_ioc', 'unsupported_attribution'],
    },
    confidenceBehavior: {
      defaultForObservations: 0.8,
      defaultForInferences: 0.5,
      defaultForUnknowns: 0,
      minimumForConclusionClaim: 0.9,
      downgradesOnUnattestedClaim: true,
      neverAbove: 0.8,
    },
    failureBehavior: {
      transientRetry: true,
      maxRetries: 1,
      onExhausted: 'fail_task_and_record_open_question',
      onInvalidStructuredOutput: 'reject_and_retry',
      onAmbiguity: 'emit_unknown_classification_only',
    },
    completionCriteria: {
      minimumEvidenceItems: 1,
      minimumDistinctProvenanceSources: 1,
      mustAcknowledgeUnknowns: true,
      mustCiteProvenancePerEvidence: true,
      mustReferenceHumanConstraints: true,
      outputShapeValid: true,
    },
    allowedFindingTypes: ['OBSERVATION', 'INFERENCE'],
    forbiddenFindingTypes: ['CONCLUSION'],
    systemPrompt:
      'You are the Identity Investigator. You only answer identity-plane questions (auth, MFA, privilege, accounts). ' +
      'Every evidence item must include provenance. Account takeover is an inference, not an observation.',
    negativePrompt:
      'Do not invent user IDs, MFA outcomes, or role grants. Do not make endpoint or network claims.',
  },

  'Threat Intelligence Investigator': {
    role: 'Threat Intelligence Investigator',
    displayName: 'Threat Intelligence Investigator',
    shortLabel: 'Threat Intel',
    capabilityScope:
      'External enrichment suitability, indicator classification, known-campaign correlation. Local-only classification in V1. No evidence authorship, no host/network/identity claims of its own.',
    objective:
      'Determine whether observed indicators are eligible for enrichment and whether they correlate with known patterns, without claiming external facts the system has not actually retrieved.',
    allowedTools: {
      capabilities: ['lookup_indicator'],
      toolCategories: ['analysis:safe-only', 'investigation:read', 'investigation:write_evidence', 'investigation:write_note', 'investigation:write_question'],
      forbidden: ['destructive_action', 'remote_execution', 'credential_use', 'autonomous_remediation'],
    },
    inputSchema: scopeFields(
      { path: 'investigation.objective', type: 'string', description: 'Investigation objective.' },
      { path: 'intel.indicators', type: 'string[]', description: 'Indicators to classify and assess for enrichment.' },
      { path: 'intel.evidenceIds', type: 'string[]', description: 'Investigation evidence IDs referencing these indicators.', required: false }
    ),
    outputSchema: outputSpec(
      { path: 'summary', type: 'string', classification: 'OBSERVED', description: 'Plain-language summary of indicator classification only.' },
      { path: 'evidence[].classification', type: 'object', classification: 'OBSERVED', description: 'Indicator classification record (local).', required: false },
      { path: 'inferences', type: 'object[]', classification: 'INFERRED', description: 'Hypothetical correlation suggestions explicitly marked unverified.', required: false },
      { path: 'unknowns', type: 'object[]', classification: 'UNKNOWN', description: 'Questions that require actual vendor retrieval.', required: false }
    ),
    evidenceResponsibility: {
      classification: 'OBSERVED',
      mustInclude: ['capability_used', 'timestamp'],
      mayNotInclude: ['fabricated_ioc', 'unsupported_attribution'],
    },
    confidenceBehavior: {
      defaultForObservations: 0.7,
      defaultForInferences: 0.3,
      defaultForUnknowns: 0,
      minimumForConclusionClaim: 1,
      downgradesOnUnattestedClaim: true,
      neverAbove: 0.6,
    },
    failureBehavior: {
      transientRetry: true,
      maxRetries: 1,
      onExhausted: 'fail_task_and_record_open_question',
      onInvalidStructuredOutput: 'reject_and_retry',
      onAmbiguity: 'emit_unknown_classification_only',
    },
    completionCriteria: {
      minimumEvidenceItems: 0,
      minimumDistinctProvenanceSources: 1,
      mustAcknowledgeUnknowns: true,
      mustCiteProvenancePerEvidence: true,
      mustReferenceHumanConstraints: true,
      outputShapeValid: true,
    },
    allowedFindingTypes: ['OBSERVATION', 'INFERENCE'],
    forbiddenFindingTypes: ['CONCLUSION'],
    systemPrompt:
      'You are the Threat Intelligence Investigator. In V1 you only classify indicators locally and assess enrichment eligibility. ' +
      'Never assert that an indicator is malicious based on memory. Never reproduce specific vendor attribution as fact. ' +
      'Mark anything not directly derived from a capability output as INFERRED or UNKNOWN.',
    negativePrompt:
      'Do not invent campaign names, actor names, or CVE attributions. Do not produce endpoint, network, or identity evidence.',
  },

  'Historical Investigator': {
    role: 'Historical Investigator',
    displayName: 'Historical Investigator',
    shortLabel: 'Historical',
    capabilityScope:
      'Comparison against historical snapshots and known baselines. No live evidence authorship, no external enrichment.',
    objective:
      'Compare current investigation indicators against previously observed behavior and call out deviations as inferences, never as conclusions.',
    allowedTools: {
      capabilities: ['search_historical_activity', 'search_browser_data', 'execute_safe_analysis'],
      toolCategories: ['filesystem:read', 'analysis:safe-only', 'investigation:read', 'investigation:write_evidence', 'investigation:write_note', 'investigation:write_question'],
      forbidden: ['destructive_action', 'remote_execution', 'credential_use', 'autonomous_remediation', ],
    },
    inputSchema: scopeFields(
      { path: 'investigation.objective', type: 'string', description: 'Investigation objective.' },
      { path: 'historical.baselineSource', type: 'string', description: 'Path to historical baseline / snapshot source.', required: false },
      { path: 'historical.entitiesToCompare', type: 'string[]', description: 'Entities whose historical behavior is in scope.', required: false }
    ),
    outputSchema: outputSpec(
      { path: 'summary', type: 'string', classification: 'OBSERVED', description: 'Plain-language summary of baseline comparison.' },
      { path: 'evidence[].baseline', type: 'object', classification: 'OBSERVED', description: 'Baseline rows.', required: false },
      { path: 'inferences', type: 'object[]', classification: 'INFERRED', description: 'Deviations and anomaly claims.', required: false },
      { path: 'unknowns', type: 'object[]', classification: 'UNKNOWN', description: 'Gaps where no baseline exists.', required: false }
    ),
    evidenceResponsibility: {
      classification: 'OBSERVED',
      mustInclude: ['source_path', 'excerpt', 'capability_used', 'timestamp'],
      mayNotInclude: ['fabricated_ioc', 'phantom_ip', 'unsupported_attribution'],
    },
    confidenceBehavior: {
      defaultForObservations: 0.8,
      defaultForInferences: 0.4,
      defaultForUnknowns: 0,
      minimumForConclusionClaim: 0.95,
      downgradesOnUnattestedClaim: true,
      neverAbove: 0.7,
    },
    failureBehavior: {
      transientRetry: true,
      maxRetries: 1,
      onExhausted: 'fail_task_and_record_open_question',
      onInvalidStructuredOutput: 'reject_and_retry',
      onAmbiguity: 'emit_unknown_classification_only',
    },
    completionCriteria: {
      minimumEvidenceItems: 0,
      minimumDistinctProvenanceSources: 1,
      mustAcknowledgeUnknowns: true,
      mustCiteProvenancePerEvidence: true,
      mustReferenceHumanConstraints: true,
      outputShapeValid: true,
    },
    allowedFindingTypes: ['OBSERVATION', 'INFERENCE'],
    forbiddenFindingTypes: ['CONCLUSION'],
    systemPrompt:
      'You are the Historical Investigator. You only compare current evidence against baselines and prior snapshots. ' +
      'If a baseline is missing, say UNKNOWN. "Unusual" is an inference, not a fact.',
    negativePrompt:
      'Do not fabricate baselines. Do not make endpoint, network, or identity claims.',
  },

  'Evidence Analyst': {
    role: 'Evidence Analyst',
    displayName: 'Synthesizer (Evidence Analyst)',
    shortLabel: 'Synthesizer',
    capabilityScope:
      'Combines evidence already produced by other investigators. May not author new host/network/identity/intel observations. May not invent facts.',
    objective:
      'Combine existing evidence items into a coherent picture, flag contradictions, and surface open questions without inventing evidence.',
    allowedTools: {
      capabilities: [],
      toolCategories: ['investigation:read', 'investigation:write_note', 'investigation:write_question'],
      forbidden: ['destructive_action', 'remote_execution', 'credential_use', 'autonomous_remediation', ],
    },
    inputSchema: scopeFields(
      { path: 'investigation.objective', type: 'string', description: 'Investigation objective.' },
      { path: 'synthesis.evidenceIds', type: 'string[]', description: 'Evidence IDs the synthesizer may use.', required: false }
    ),
    outputSchema: outputSpec(
      { path: 'summary', type: 'string', classification: 'OBSERVED', description: 'Synthesized summary strictly derived from referenced evidence.' },
      { path: 'inferences', type: 'object[]', classification: 'INFERRED', description: 'Cross-source inferences with citations to source evidence IDs.', required: false },
      { path: 'unknowns', type: 'object[]', classification: 'UNKNOWN', description: 'Gaps and unresolved questions.', required: false }
    ),
    evidenceResponsibility: {
      classification: 'OBSERVED',
      mustInclude: ['entity_ids'],
      mayNotInclude: ['fabricated_ioc', 'phantom_process', 'phantom_ip', 'phantom_user', 'unsupported_attribution'],
    },
    confidenceBehavior: {
      defaultForObservations: 0.7,
      defaultForInferences: 0.5,
      defaultForUnknowns: 0,
      minimumForConclusionClaim: 1,
      downgradesOnUnattestedClaim: true,
      neverAbove: 0.6,
    },
    failureBehavior: {
      transientRetry: false,
      maxRetries: 0,
      onExhausted: 'block_synthesis_and_report',
      onInvalidStructuredOutput: 'reject_and_record_note',
      onAmbiguity: 'emit_unknown_classification_only',
    },
    completionCriteria: {
      minimumEvidenceItems: 0,
      minimumDistinctProvenanceSources: 0,
      mustAcknowledgeUnknowns: true,
      mustCiteProvenancePerEvidence: true,
      mustReferenceHumanConstraints: true,
      outputShapeValid: true,
    },
    allowedFindingTypes: ['OBSERVATION', 'INFERENCE'],
    forbiddenFindingTypes: ['CONCLUSION'],
    systemPrompt:
      'You are the Synthesizer. You only combine evidence other investigators already produced. ' +
      'Every claim must cite an existing evidence ID. If the underlying evidence is missing, mark UNKNOWN. ' +
      'You never invent facts and you never emit a CONCLUSION finding type.',
    negativePrompt:
      'Do not add new facts. Do not raise confidence above the underlying evidence. Do not attribute.',
  },

  'Research Investigator': {
    role: 'Research Investigator',
    displayName: 'Research Investigator',
    shortLabel: 'Research',
    capabilityScope:
      'Technique, tradecraft, and environmental context lookup. No live evidence authorship about the incident itself.',
    objective:
      'Provide general technique and context notes that may help investigators frame findings, clearly marked as background only.',
    allowedTools: {
      capabilities: ['lookup_indicator'],
      toolCategories: ['analysis:safe-only', 'investigation:read', 'investigation:write_note', 'investigation:write_question'],
      forbidden: ['destructive_action', 'remote_execution', 'credential_use', 'autonomous_remediation'],
    },
    inputSchema: scopeFields(
      { path: 'investigation.objective', type: 'string', description: 'Investigation objective.' },
      { path: 'research.focus', type: 'string', description: 'What to research.' }
    ),
    outputSchema: outputSpec(
      { path: 'summary', type: 'string', classification: 'OBSERVED', description: 'Background summary with explicit unverified markers.' },
      { path: 'inferences', type: 'object[]', classification: 'INFERRED', description: 'Background framings.', required: false },
      { path: 'unknowns', type: 'object[]', classification: 'UNKNOWN', description: 'What must be verified before any production use.', required: false }
    ),
    evidenceResponsibility: {
      classification: 'OBSERVED',
      mustInclude: ['capability_used'],
      mayNotInclude: ['fabricated_ioc', 'unsupported_attribution'],
    },
    confidenceBehavior: {
      defaultForObservations: 0.5,
      defaultForInferences: 0.3,
      defaultForUnknowns: 0,
      minimumForConclusionClaim: 1,
      downgradesOnUnattestedClaim: true,
      neverAbove: 0.5,
    },
    failureBehavior: {
      transientRetry: true,
      maxRetries: 1,
      onExhausted: 'fail_task_and_record_open_question',
      onInvalidStructuredOutput: 'reject_and_retry',
      onAmbiguity: 'emit_unknown_classification_only',
    },
    completionCriteria: {
      minimumEvidenceItems: 0,
      minimumDistinctProvenanceSources: 1,
      mustAcknowledgeUnknowns: true,
      mustCiteProvenancePerEvidence: true,
      mustReferenceHumanConstraints: true,
      outputShapeValid: true,
    },
    allowedFindingTypes: ['OBSERVATION', 'INFERENCE'],
    forbiddenFindingTypes: ['CONCLUSION'],
    systemPrompt:
      'You are the Research Investigator. You only provide background technique and context. ' +
      'You never produce incident evidence and never claim a specific environment matches a tradecraft.',
    negativePrompt:
      'Do not invent attribution. Do not produce endpoint, network, or identity evidence.',
  },

  Challenger: {
    role: 'Challenger',
    displayName: 'Challenger',
    shortLabel: 'Challenger',
    capabilityScope:
      'Critiques existing hypotheses and evidence. Reads everything but writes only contradictions, alternative explanations, and falsification conditions.',
    objective:
      'Search for contradictory evidence, weak assumptions, alternative explanations, and missing evidence that would falsify the leading hypothesis.',
    allowedTools: {
      capabilities: [],
      toolCategories: ['investigation:read', 'investigation:write_note', 'investigation:write_question'],
      forbidden: ['destructive_action', 'remote_execution', 'credential_use', 'autonomous_remediation', ],
    },
    inputSchema: scopeFields(
      { path: 'investigation.objective', type: 'string', description: 'Investigation objective.' },
      { path: 'challenge.targetHypothesisId', type: 'string', description: 'Hypothesis to challenge.', required: false }
    ),
    outputSchema: outputSpec(
      { path: 'summary', type: 'string', classification: 'OBSERVED', description: 'Critique summary.' },
      { path: 'inferences', type: 'object[]', classification: 'INFERRED', description: 'Alternative explanations and contradictions.', required: false },
      { path: 'unknowns', type: 'object[]', classification: 'UNKNOWN', description: 'Falsification conditions and missing evidence.', required: false }
    ),
    evidenceResponsibility: {
      classification: 'OBSERVED',
      mustInclude: ['entity_ids'],
      mayNotInclude: ['fabricated_ioc', 'phantom_process', 'phantom_ip', 'phantom_user', 'unsupported_attribution'],
    },
    confidenceBehavior: {
      defaultForObservations: 0.6,
      defaultForInferences: 0.4,
      defaultForUnknowns: 0,
      minimumForConclusionClaim: 1,
      downgradesOnUnattestedClaim: true,
      neverAbove: 0.6,
    },
    failureBehavior: {
      transientRetry: false,
      maxRetries: 0,
      onExhausted: 'block_synthesis_and_report',
      onInvalidStructuredOutput: 'reject_and_record_note',
      onAmbiguity: 'emit_unknown_classification_only',
    },
    completionCriteria: {
      minimumEvidenceItems: 0,
      minimumDistinctProvenanceSources: 0,
      mustAcknowledgeUnknowns: true,
      mustCiteProvenancePerEvidence: true,
      mustReferenceHumanConstraints: true,
      outputShapeValid: true,
    },
    allowedFindingTypes: ['OBSERVATION', 'INFERENCE'],
    forbiddenFindingTypes: ['CONCLUSION'],
    systemPrompt:
      'You are the Challenger. Your only job is to find contradictions, weak assumptions, alternative explanations, and missing evidence. ' +
      'You never endorse a hypothesis. You never invent evidence. You only cite existing evidence IDs.',
    negativePrompt:
      'Do not invent facts. Do not endorse the leading hypothesis. Do not produce new evidence.',
  },
};

export function getAgentDefinition(role: InvestigationAgentRole): CyberAgentDefinition {
  const definition = CYBER_AGENT_DEFINITIONS[role];
  if (!definition) {
    throw new Error(`No agent definition registered for role: ${role}`);
  }
  return definition;
}

export function listAgentDefinitions(): CyberAgentDefinition[] {
  return Object.values(CYBER_AGENT_DEFINITIONS);
}


