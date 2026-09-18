import type { InvestigationAgentRole } from '../investigation/parallel-investigation-engine';
import {
  EVIDENCE_CLASSIFICATIONS,
  type AgentCompletionCriteria,
  type AgentConfidenceBehavior,
  type AgentEvidenceResponsibility,
  type AgentFailureBehavior,
  type AgentOutputSchemaField,
  type CyberAgentDefinition,
  type EvidenceClassification,
  getAgentDefinition,
} from './cyber-agent-definitions';

export interface AgentOutputValidationIssue {
  path: string;
  code:
    | 'missing_required_field'
    | 'invalid_classification'
    | 'forbidden_finding_type'
    | 'missing_provenance'
    | 'confidence_out_of_range'
    | 'unattested_claim'
    | 'unknowns_missing';
  message: string;
}

export interface AgentOutputValidationResult {
  ok: boolean;
  issues: AgentOutputValidationIssue[];
  classificationCounts: Record<EvidenceClassification, number>;
  hasUnknowns: boolean;
  hasObservations: boolean;
  hasInferences: boolean;
}

const FORBIDDEN_PHANTOM_PATTERNS: ReadonlyArray<{ pattern: RegExp; label: string }> = [
  { pattern: /\b192\.168\.0\.1\b/g, label: 'common-rfc1918-default' },
  { pattern: /\b10\.0\.0\.1\b/g, label: 'common-rfc1918-default' },
  { pattern: /\b8\.8\.8\.8\b/g, label: 'placeholder-public-dns' },
];

export class CyberAgentOutputValidator {
  validate(role: InvestigationAgentRole, value: unknown): AgentOutputValidationResult {
    const definition = getAgentDefinition(role);
    const issues: AgentOutputValidationIssue[] = [];

    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return emptyResult([
        {
          path: '',
          code: 'missing_required_field',
          message: 'agent output must be a JSON object',
        },
      ]);
    }

    const record = value as Record<string, unknown>;
    const summary = record.summary;
    const evidence = Array.isArray(record.evidence) ? record.evidence : [];
    const inferences = Array.isArray(record.inferences) ? record.inferences : [];
    const unknowns = Array.isArray(record.unknowns) ? record.unknowns : [];
    const hypothesisUpdates = Array.isArray(record.hypothesisUpdates) ? record.hypothesisUpdates : [];

    if (typeof summary !== 'string' || summary.trim().length === 0) {
      issues.push({
        path: 'summary',
        code: 'missing_required_field',
        message: 'summary is required and must be a non-empty string',
      });
    }

    for (const field of definition.outputSchema) {
      const valueAt = readPath(record, field.path);
      if (valueAt === undefined) {
        if (field.required) {
          issues.push({
            path: field.path,
            code: 'missing_required_field',
            message: `required output field "${field.path}" is missing`,
          });
        }
        continue;
      }
      issues.push(...validateFieldType(field, valueAt));
    }

    for (const item of evidence) {
      issues.push(...validateEvidenceItem(item, definition.evidenceResponsibility));
    }

    for (const update of hypothesisUpdates) {
      issues.push(...validateHypothesisUpdate(update, definition));
    }

    if (definition.completionCriteria.mustAcknowledgeUnknowns && unknowns.length === 0) {
      issues.push({
        path: 'unknowns',
        code: 'unknowns_missing',
        message: `${role} must explicitly emit at least one UNKNOWN when it cannot answer authoritatively`,
      });
    }

    if (
      definition.completionCriteria.minimumEvidenceItems > 0 &&
      evidence.length < definition.completionCriteria.minimumEvidenceItems &&
      unknowns.length === 0
    ) {
      issues.push({
        path: 'evidence',
        code: 'missing_required_field',
        message: `${role} requires at least ${definition.completionCriteria.minimumEvidenceItems} evidence item(s) or an explicit UNKNOWN`,
      });
    }

    issues.push(...enforceConfidenceBehavior(record, definition.confidenceBehavior));
    issues.push(...enforceFailureBehaviors(record, definition.failureBehavior));

    const counts: Record<EvidenceClassification, number> = { OBSERVED: 0, INFERRED: 0, UNKNOWN: 0 };
    for (const item of evidence) {
      const classification = readClassification(item);
      if (classification) counts[classification] += 1;
    }
    for (const item of inferences) {
      if (item !== undefined) counts.INFERRED += 1;
    }
    for (const item of unknowns) {
      if (item !== undefined) counts.UNKNOWN += 1;
    }

    return {
      ok: issues.length === 0,
      issues,
      classificationCounts: counts,
      hasUnknowns: counts.UNKNOWN > 0,
      hasObservations: counts.OBSERVED > 0,
      hasInferences: counts.INFERRED > 0,
    };
  }
}

export function validateAgentOutput(
  role: InvestigationAgentRole,
  value: unknown
): AgentOutputValidationResult {
  return new CyberAgentOutputValidator().validate(role, value);
}

function emptyResult(issues: AgentOutputValidationIssue[]): AgentOutputValidationResult {
  return {
    ok: false,
    issues,
    classificationCounts: { OBSERVED: 0, INFERRED: 0, UNKNOWN: 0 },
    hasUnknowns: false,
    hasObservations: false,
    hasInferences: false,
  };
}

function readPath(record: Record<string, unknown>, path: string): unknown {
  if (!path.includes('[')) return record[path];
  const segments = path.split('.');
  let current: unknown = record;
  for (const segment of segments) {
    if (!current || typeof current !== 'object') return undefined;
    const arrayMatch = /^([\w$]+)(?:\[(\d+)\])?$/.exec(segment);
    if (!arrayMatch) return undefined;
    const key = arrayMatch[1];
    current = (current as Record<string, unknown>)[key];
    const index = arrayMatch[2];
    if (index !== undefined) {
      if (!Array.isArray(current)) return undefined;
      current = current[Number(index)];
    }
  }
  return current;
}

function validateFieldType(field: AgentOutputSchemaField, value: unknown): AgentOutputValidationIssue[] {
  const issues: AgentOutputValidationIssue[] = [];
  const t = field.type;
  if (t === 'string' && typeof value !== 'string') {
    issues.push({ path: field.path, code: 'missing_required_field', message: `${field.path} must be a string` });
  } else if (t === 'number' && typeof value !== 'number') {
    issues.push({ path: field.path, code: 'missing_required_field', message: `${field.path} must be a number` });
  } else if (t === 'boolean' && typeof value !== 'boolean') {
    issues.push({ path: field.path, code: 'missing_required_field', message: `${field.path} must be a boolean` });
  } else if (t === 'string[]' && !(Array.isArray(value) && value.every((item) => typeof item === 'string'))) {
    issues.push({ path: field.path, code: 'missing_required_field', message: `${field.path} must be an array of strings` });
  } else if (t === 'object' && (typeof value !== 'object' || value === null || Array.isArray(value))) {
    issues.push({ path: field.path, code: 'missing_required_field', message: `${field.path} must be an object` });
  } else if (t === 'object[]' && !(Array.isArray(value) && value.every((item) => typeof item === 'object' && item !== null && !Array.isArray(item)))) {
    issues.push({ path: field.path, code: 'missing_required_field', message: `${field.path} must be an array of objects` });
  }
  return issues;
}

function readClassification(item: unknown): EvidenceClassification | null {
  if (!item || typeof item !== 'object') return null;
  const record = item as Record<string, unknown>;
  const value = record.classification || record.type;
  if (typeof value !== 'string') return null;
  if ((EVIDENCE_CLASSIFICATIONS as readonly string[]).includes(value)) return value as EvidenceClassification;
  return null;
}

function validateEvidenceItem(
  item: unknown,
  responsibility: AgentEvidenceResponsibility
): AgentOutputValidationIssue[] {
  const issues: AgentOutputValidationIssue[] = [];
  if (!item || typeof item !== 'object' || Array.isArray(item)) {
    issues.push({
      path: 'evidence[*]',
      code: 'missing_required_field',
      message: 'evidence items must be objects',
    });
    return issues;
  }

  const evidence = item as Record<string, unknown>;
  const type = evidence.type;
  if (typeof type === 'string' && type === 'CONCLUSION') {
    issues.push({
      path: 'evidence[*].type',
      code: 'forbidden_finding_type',
      message: 'CONCLUSION is reserved for human-confirmed final answers, not agent evidence',
    });
  }

  const classification = readClassification(evidence);
  if (classification === null) {
    issues.push({
      path: 'evidence[*].classification',
      code: 'invalid_classification',
      message: 'evidence must declare classification OBSERVED | INFERRED | UNKNOWN',
    });
  }

  for (const field of responsibility.mustInclude) {
    if (!hasProvenanceField(evidence, field)) {
      issues.push({
        path: `evidence[*].provenance.${field}`,
        code: 'missing_provenance',
        message: `evidence missing required provenance field "${field}"`,
      });
    }
  }

  issues.push(...checkPhantomIndicators(evidence, responsibility));

  return issues;
}

function hasProvenanceField(evidence: Record<string, unknown>, field: string): boolean {
  const direct = evidence[field];
  if (direct !== undefined && direct !== null && direct !== '') return true;
  const provenance = evidence.provenance;
  if (provenance && typeof provenance === 'object') {
    const value = (provenance as Record<string, unknown>)[field];
    if (value !== undefined && value !== null && value !== '') return true;
  }
  const details = evidence.details;
  if (details && typeof details === 'object') {
    const value = (details as Record<string, unknown>)[field];
    if (value !== undefined && value !== null && value !== '') return true;
  }
  return false;
}

function checkPhantomIndicators(
  evidence: Record<string, unknown>,
  responsibility: AgentEvidenceResponsibility
): AgentOutputValidationIssue[] {
  if (!responsibility.mayNotInclude.length) return [];
  const text = JSON.stringify(evidence);
  const issues: AgentOutputValidationIssue[] = [];
  for (const forbidden of responsibility.mayNotInclude) {
    if (forbidden === 'phantom_ip') {
      for (const { pattern, label } of FORBIDDEN_PHANTOM_PATTERNS) {
        if (pattern.test(text)) {
          issues.push({
            path: 'evidence[*]',
            code: 'unattested_claim',
            message: `evidence contains placeholder IP pattern (${label}); phantom IPs are not allowed`,
          });
        }
      }
    }
    if (forbidden === 'fabricated_ioc' && /\bCVE-\d{4}-\d{4,}\b/.test(text)) {
      const provenanceOk = hasProvenanceField(evidence, 'sourceLabel') || hasProvenanceField(evidence, 'capability');
      if (!provenanceOk) {
        issues.push({
          path: 'evidence[*]',
          code: 'unattested_claim',
          message: 'fabricated CVE reference without provenance is not allowed',
        });
      }
    }
  }
  return issues;
}

function validateHypothesisUpdate(
  update: unknown,
  definition: CyberAgentDefinition
): AgentOutputValidationIssue[] {
  if (!update || typeof update !== 'object') return [];
  const record = update as Record<string, unknown>;
  const issues: AgentOutputValidationIssue[] = [];
  if (record.status === 'PROMOTED') {
    issues.push({
      path: 'hypothesisUpdates[*].status',
      code: 'forbidden_finding_type',
      message: `${definition.role} may not PROMOTE hypotheses; only humans may`,
    });
  }
  if (typeof record.confidence === 'number' && record.confidence > definition.confidenceBehavior.neverAbove) {
    issues.push({
      path: 'hypothesisUpdates[*].confidence',
      code: 'confidence_out_of_range',
      message: `${definition.role} confidence ${record.confidence} exceeds neverAbove ${definition.confidenceBehavior.neverAbove}`,
    });
  }
  return issues;
}

function enforceConfidenceBehavior(
  record: Record<string, unknown>,
  confidence: AgentConfidenceBehavior
): AgentOutputValidationIssue[] {
  const issues: AgentOutputValidationIssue[] = [];
  for (const item of readArray(record, 'evidence')) {
    if (!item || typeof item !== 'object') continue;
    const r = item as Record<string, unknown>;
    const cls = readClassification(r);
    if (typeof r.confidence === 'number') {
      if (cls === 'OBSERVED' && r.confidence > confidence.neverAbove) {
        issues.push({
          path: 'evidence[*].confidence',
          code: 'confidence_out_of_range',
          message: `OBSERVED confidence ${r.confidence} exceeds agent cap ${confidence.neverAbove}`,
        });
      }
      if (cls === 'INFERRED' && r.confidence > Math.max(confidence.defaultForInferences, confidence.neverAbove)) {
        issues.push({
          path: 'evidence[*].confidence',
          code: 'confidence_out_of_range',
          message: `INFERRED confidence ${r.confidence} exceeds inference cap`,
        });
      }
      if (cls === 'UNKNOWN' && r.confidence !== 0) {
        issues.push({
          path: 'evidence[*].confidence',
          code: 'confidence_out_of_range',
          message: `UNKNOWN evidence must have confidence 0`,
        });
      }
    }
  }
  return issues;
}

function enforceFailureBehaviors(
  record: Record<string, unknown>,
  failure: AgentFailureBehavior
): AgentOutputValidationIssue[] {
  const issues: AgentOutputValidationIssue[] = [];
  if (failure.onAmbiguity === 'emit_unknown_classification_only') {
    if (!readArray(record, 'unknowns').length && !readArray(record, 'evidence').length) {
      issues.push({
        path: 'unknowns',
        code: 'unknowns_missing',
        message: 'agent must emit UNKNOWN evidence on ambiguity, not silently omit',
      });
    }
  }
  return issues;
}

function readArray(record: Record<string, unknown>, key: string): unknown[] {
  const value = record[key];
  return Array.isArray(value) ? value : [];
}

void ({} as AgentCompletionCriteria);