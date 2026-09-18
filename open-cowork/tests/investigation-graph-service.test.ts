import { describe, expect, it } from 'vitest';
import type { Investigation, InvestigationEntity, InvestigationEvidence } from '../src/shared/cyber/investigation-types';
import { InvestigationGraphService } from '../src/main/investigation/investigation-graph-service';

function makeEntity(id: string, name: string, type: InvestigationEntity['type']): InvestigationEntity {
  return {
    id,
    name,
    type,
    createdAt: 1_700_000_000_000,
  };
}

function makeEvidence(id: string, relatedEntityIds: string[]): InvestigationEvidence {
  return {
    id,
    investigationId: 'inv-1',
    type: 'OBSERVATION',
    title: id,
    source: 'test',
    timestamp: 1_700_000_000_000,
    collectedAt: 1_700_000_000_100,
    investigator: 'tester',
    relatedEntityIds,
    content: id,
    confidence: 0.8,
    provenance: {
      method: 'tool_output',
      sourceType: 'file',
    },
    hypothesisIds: [],
    analystAnnotations: [],
    relationships: [],
    kind: 'structured_record',
    summary: id,
    tags: [],
  };
}

function makeInvestigation(): Investigation {
  return {
    id: 'inv-1',
    title: 'Case',
    objective: 'Obj',
    status: 'INVESTIGATING',
    createdAt: 1,
    updatedAt: 1,
    humanContext: '',
    humanCapabilityContext: {
      environmentalKnowledge: [],
      priorities: [],
      constraints: [],
      suspicions: [],
      knownLegitimateBehavior: [],
      knownAbnormalBehavior: [],
      riskTolerance: 'MEDIUM',
      importantEntityIds: [],
      importantEntities: [],
      investigationDirections: [],
      notes: [],
    },
    hypotheses: [],
    evidence: [
      makeEvidence('ev-process-host', ['proc-1', 'host-1']),
      makeEvidence('ev-account-host', ['acct-1', 'host-2']),
      makeEvidence('ev-process-ip', ['proc-1', 'ip-1']),
    ],
    entities: [
      makeEntity('proc-1', 'powershell.exe', 'process'),
      makeEntity('host-1', 'Workstation-22', 'host'),
      makeEntity('host-2', 'Server-03', 'host'),
      makeEntity('acct-1', 'svc-backup', 'account'),
      makeEntity('ip-1', '203.0.113.50', 'ip'),
    ],
    graph: { relationships: [] },
    timeline: [],
    openQuestions: [],
    aiTasks: [],
    humanTasks: [],
    decisions: [],
    conclusions: [],
    confidence: 0,
    activity: [],
  };
}

describe('InvestigationGraphService', () => {
  it('adds evidence-backed graph relationships', () => {
    const service = new InvestigationGraphService();
    const investigation = makeInvestigation();

    const result = service.addRelationship(investigation, {
      type: 'EXECUTED',
      sourceEntityId: 'proc-1',
      targetEntityId: 'host-1',
      source: 'process telemetry',
      timestamp: 1_700_000_000_000,
      confidence: 0.91,
      evidenceIds: ['ev-process-host'],
    });

    expect(result.graph.relationships).toHaveLength(1);
    expect(result.relationship.evidenceIds).toEqual(['ev-process-host']);
    expect(result.relationship.confidence).toBe(0.91);
  });

  it('finds connected entities within a time window', () => {
    const service = new InvestigationGraphService();
    let investigation = makeInvestigation();

    investigation = {
      ...investigation,
      graph: {
        relationships: [
          service.addRelationship(investigation, {
            type: 'CONNECTED_TO',
            sourceEntityId: 'proc-1',
            targetEntityId: 'ip-1',
            source: 'netflow',
            timestamp: 1_000,
            confidence: 0.8,
            evidenceIds: ['ev-process-ip'],
          }).relationship,
          service.addRelationship(investigation, {
            type: 'EXECUTED',
            sourceEntityId: 'proc-1',
            targetEntityId: 'host-1',
            source: 'process telemetry',
            timestamp: 1_005,
            confidence: 0.95,
            evidenceIds: ['ev-process-host'],
          }).relationship,
          service.addRelationship(investigation, {
            type: 'AUTHENTICATED_TO',
            sourceEntityId: 'acct-1',
            targetEntityId: 'host-2',
            source: 'auth log',
            timestamp: 2_000,
            confidence: 0.88,
            evidenceIds: ['ev-account-host'],
          }).relationship,
        ],
      },
    };

    const connected = service.findEntitiesConnectedWithinTimeWindow(investigation, {
      entityId: 'proc-1',
      withinMs: 10,
      direction: 'both',
    });

    expect(connected.map((item) => item.entity.id).sort()).toEqual(['host-1', 'ip-1']);
  });

  it('supports relationship queries for an account contacting hosts', () => {
    const service = new InvestigationGraphService();
    const investigation = makeInvestigation();
    const accountToHost = service.addRelationship(investigation, {
      type: 'AUTHENTICATED_TO',
      sourceEntityId: 'acct-1',
      targetEntityId: 'host-2',
      source: 'auth log',
      timestamp: 1_700_000_000_500,
      confidence: 0.84,
      evidenceIds: ['ev-account-host'],
    });

    const next: Investigation = {
      ...investigation,
      graph: accountToHost.graph,
    };

    const neighbors = service.findConnectedEntities(next, {
      entityId: 'acct-1',
      direction: 'outbound',
      relationshipTypes: ['AUTHENTICATED_TO'],
    });

    expect(neighbors).toHaveLength(1);
    expect(neighbors[0]?.entity.id).toBe('host-2');
  });

  it('returns evidence supporting a graph relationship', () => {
    const service = new InvestigationGraphService();
    const investigation = makeInvestigation();
    const added = service.addRelationship(investigation, {
      type: 'CONNECTED_TO',
      sourceEntityId: 'proc-1',
      targetEntityId: 'ip-1',
      source: 'netflow',
      timestamp: 1_700_000_000_250,
      confidence: 0.74,
      evidenceIds: ['ev-process-ip'],
    });

    const next: Investigation = {
      ...investigation,
      graph: added.graph,
    };

    const evidence = service.getEvidenceForRelationship(next, added.relationship.id);
    expect(evidence.map((item) => item.id)).toEqual(['ev-process-ip']);
  });
});
