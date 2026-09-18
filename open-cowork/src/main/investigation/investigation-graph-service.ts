import { v4 as uuidv4 } from 'uuid';
import type {
  Investigation,
  InvestigationEntity,
  InvestigationEvidence,
  InvestigationEvidenceGraph,
  InvestigationGraphRelationship,
  InvestigationGraphRelationshipType,
} from '../../shared/cyber/investigation-types';

function clampConfidence(value: number | undefined): number {
  if (typeof value !== 'number' || Number.isNaN(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

function defaultGraph(): InvestigationEvidenceGraph {
  return { relationships: [] };
}

export interface AddGraphRelationshipInput {
  type: InvestigationGraphRelationshipType;
  sourceEntityId: string;
  targetEntityId: string;
  source: string;
  timestamp?: number;
  confidence?: number;
  evidenceIds?: string[];
  supportingTaskId?: string;
  investigator?: string;
  direction?: InvestigationGraphRelationship['direction'];
  metadata?: Record<string, unknown>;
}

export interface GraphNeighborQuery {
  entityId: string;
  relationshipTypes?: InvestigationGraphRelationshipType[];
  direction?: 'outbound' | 'inbound' | 'both';
  startTime?: number;
  endTime?: number;
}

export interface GraphTemporalConnectionQuery {
  entityId: string;
  withinMs: number;
  relationshipTypes?: InvestigationGraphRelationshipType[];
  direction?: 'outbound' | 'inbound' | 'both';
  anchorTimestamp?: number;
}

export class InvestigationGraphService {
  getGraph(investigation: Investigation): InvestigationEvidenceGraph {
    return {
      relationships: Array.isArray(investigation.graph?.relationships)
        ? investigation.graph.relationships.map((relationship) => ({
            ...relationship,
            confidence: clampConfidence(relationship.confidence),
            evidenceIds: Array.isArray(relationship.evidenceIds) ? relationship.evidenceIds : [],
          }))
        : defaultGraph().relationships,
    };
  }

  addRelationship(
    investigation: Investigation,
    input: AddGraphRelationshipInput,
    now = Date.now()
  ): { graph: InvestigationEvidenceGraph; relationship: InvestigationGraphRelationship } {
    this.assertEntityExists(investigation.entities, input.sourceEntityId);
    this.assertEntityExists(investigation.entities, input.targetEntityId);
    this.assertEvidenceIdsExist(investigation.evidence, input.evidenceIds || []);

    const relationship: InvestigationGraphRelationship = {
      id: uuidv4(),
      type: input.type,
      sourceEntityId: input.sourceEntityId,
      targetEntityId: input.targetEntityId,
      source: input.source.trim(),
      timestamp: input.timestamp ?? now,
      confidence: clampConfidence(input.confidence),
      evidenceIds: [...new Set((input.evidenceIds || []).filter(Boolean))],
      createdAt: now,
      supportingTaskId: input.supportingTaskId,
      investigator: input.investigator,
      direction: input.direction || 'UNKNOWN',
      metadata: input.metadata,
    };

    return {
      relationship,
      graph: {
        relationships: [...this.getGraph(investigation).relationships, relationship],
      },
    };
  }

  getRelationshipsForEntity(
    investigation: Investigation,
    query: GraphNeighborQuery
  ): InvestigationGraphRelationship[] {
    const relationships = this.getGraph(investigation).relationships.filter((relationship) => {
      const direction = query.direction || 'both';
      const typeMatches = !query.relationshipTypes?.length || query.relationshipTypes.includes(relationship.type);
      const timeMatches =
        (query.startTime === undefined || relationship.timestamp >= query.startTime) &&
        (query.endTime === undefined || relationship.timestamp <= query.endTime);
      const directionMatches =
        direction === 'both'
          ? relationship.sourceEntityId === query.entityId || relationship.targetEntityId === query.entityId
          : direction === 'outbound'
            ? relationship.sourceEntityId === query.entityId
            : relationship.targetEntityId === query.entityId;
      return typeMatches && timeMatches && directionMatches;
    });

    return relationships.sort((a, b) => a.timestamp - b.timestamp || a.createdAt - b.createdAt || a.id.localeCompare(b.id));
  }

  findConnectedEntities(
    investigation: Investigation,
    query: GraphNeighborQuery
  ): Array<{ entity: InvestigationEntity; relationships: InvestigationGraphRelationship[] }> {
    const grouped = new Map<string, InvestigationGraphRelationship[]>();
    for (const relationship of this.getRelationshipsForEntity(investigation, query)) {
      const neighborId = relationship.sourceEntityId === query.entityId ? relationship.targetEntityId : relationship.sourceEntityId;
      const list = grouped.get(neighborId) || [];
      list.push(relationship);
      grouped.set(neighborId, list);
    }

    return Array.from(grouped.entries())
      .map(([entityId, relationships]) => {
        const entity = investigation.entities.find((item) => item.id === entityId);
        return entity ? { entity, relationships } : null;
      })
      .filter((item): item is { entity: InvestigationEntity; relationships: InvestigationGraphRelationship[] } => Boolean(item))
      .sort((a, b) => a.entity.name.localeCompare(b.entity.name));
  }

  findEntitiesConnectedWithinTimeWindow(
    investigation: Investigation,
    query: GraphTemporalConnectionQuery
  ): Array<{ entity: InvestigationEntity; relationships: InvestigationGraphRelationship[] }> {
    const anchorRelationships = this.getRelationshipsForEntity(investigation, {
      entityId: query.entityId,
      relationshipTypes: query.relationshipTypes,
      direction: query.direction,
    });

    const anchorTimestamp = query.anchorTimestamp ?? anchorRelationships[0]?.timestamp;
    if (anchorTimestamp === undefined) return [];

    return this.findConnectedEntities(investigation, {
      entityId: query.entityId,
      relationshipTypes: query.relationshipTypes,
      direction: query.direction,
      startTime: anchorTimestamp - query.withinMs,
      endTime: anchorTimestamp + query.withinMs,
    });
  }

  getEvidenceForRelationship(investigation: Investigation, relationshipId: string): InvestigationEvidence[] {
    const relationship = this.getGraph(investigation).relationships.find((item) => item.id === relationshipId);
    if (!relationship) return [];
    const evidenceIds = new Set(relationship.evidenceIds);
    return investigation.evidence
      .filter((item) => evidenceIds.has(item.id))
      .sort((a, b) => a.timestamp - b.timestamp || a.collectedAt - b.collectedAt || a.id.localeCompare(b.id));
  }

  private assertEntityExists(entities: InvestigationEntity[], entityId: string): void {
    if (!entities.some((entity) => entity.id === entityId)) {
      throw new Error(`Entity not found in investigation graph: ${entityId}`);
    }
  }

  private assertEvidenceIdsExist(evidence: InvestigationEvidence[], evidenceIds: string[]): void {
    const known = new Set(evidence.map((item) => item.id));
    for (const evidenceId of evidenceIds) {
      if (!known.has(evidenceId)) {
        throw new Error(`Evidence not found for graph relationship: ${evidenceId}`);
      }
    }
  }
}
