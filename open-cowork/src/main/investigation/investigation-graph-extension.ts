import { Type } from '@sinclair/typebox';
import type { ExtensionContext } from '@mariozechner/pi-coding-agent';
import type {
  AgentRuntimeCustomTool,
  AgentRuntimeExtension,
  BeforeSessionRunContext,
  BeforeSessionRunResult,
} from '../extensions/agent-runtime-extension';
import type { InvestigationService } from './investigation-service';
import type { InvestigationGraphRelationshipType } from '../../shared/cyber/investigation-types';

function toolTextResult(text: string, details?: unknown) {
  return {
    content: [{ type: 'text' as const, text }],
    details,
  };
}

function buildPromptPrefix(): string {
  return [
    '<investigation_graph_guidance>',
    'Use the investigation graph to query structured entity relationships instead of reconstructing them from full conversation history.',
    'Prefer graph queries when you need to understand execution chains, network connections, authentication paths, related entities, or evidence-backed relationships.',
    'When making claims from graph structure, inspect the supporting evidence for the relevant relationships.',
    '</investigation_graph_guidance>',
  ].join('\n');
}

function createGraphQueryTool(
  investigationService: InvestigationService,
  sessionLookup: (sessionId: string) => string | null
): AgentRuntimeCustomTool {
  return {
    name: 'investigation_graph_query',
    label: 'investigation_graph_query',
    description:
      'Query the structured investigation evidence graph linked to the current session. Supports graph overview, entity relationship lookup, time-window connection queries, and evidence lookup for a relationship.',
    parameters: Type.Object({
      queryType: Type.String({
        description:
          'Query type: overview, relationships_for_entity, connected_entities, connected_within_window, or evidence_for_relationship.',
      }),
      entityId: Type.Optional(
        Type.String({
          description: 'Entity ID for entity-centered graph queries.',
        })
      ),
      relationshipId: Type.Optional(
        Type.String({
          description: 'Relationship ID for evidence_for_relationship queries.',
        })
      ),
      relationshipTypes: Type.Optional(
        Type.Array(Type.String({ description: 'Optional relationship type filter.' }))
      ),
      direction: Type.Optional(
        Type.String({
          description: 'Optional direction filter: outbound, inbound, or both.',
        })
      ),
      startTime: Type.Optional(Type.Number()),
      endTime: Type.Optional(Type.Number()),
      withinMs: Type.Optional(Type.Number({ minimum: 0 })),
      anchorTimestamp: Type.Optional(Type.Number()),
    }),
    async execute(_toolCallId: string, params: unknown, _signal: AbortSignal | undefined, _onUpdate: any, ctx: ExtensionContext) {
      const sessionId = ctx.sessionManager.getSessionId();
      if (!sessionId) {
        return toolTextResult('Error: session context unavailable.');
      }
      const investigationId = sessionLookup(sessionId);
      if (!investigationId) {
        return toolTextResult('No investigation is linked to this session.');
      }
      const investigation = investigationService.get(investigationId);
      if (!investigation) {
        return toolTextResult('Linked investigation not found.');
      }

      const {
        queryType,
        entityId,
        relationshipId,
        relationshipTypes,
        direction,
        startTime,
        endTime,
        withinMs,
        anchorTimestamp,
      } = (params || {}) as {
        queryType?: string;
        entityId?: string;
        relationshipId?: string;
        relationshipTypes?: string[];
        direction?: 'outbound' | 'inbound' | 'both';
        startTime?: number;
        endTime?: number;
        withinMs?: number;
        anchorTimestamp?: number;
      };

      const normalizedTypes = (relationshipTypes || []).filter(Boolean) as InvestigationGraphRelationshipType[];
      const normalizedDirection = direction || 'both';

      if (!queryType || typeof queryType !== 'string') {
        return toolTextResult('Error: queryType parameter is required.');
      }

      switch (queryType) {
        case 'overview': {
          const graph = investigationService.getGraph(investigationId);
          return toolTextResult(
            JSON.stringify(
              {
                investigationId,
                entityCount: investigation.entities.length,
                relationshipCount: graph.relationships.length,
                relationshipTypes: [...new Set(graph.relationships.map((item) => item.type))].sort(),
              },
              null,
              2
            )
          );
        }
        case 'relationships_for_entity': {
          if (!entityId) return toolTextResult('Error: entityId is required for relationships_for_entity.');
          const relationships = investigationService.getGraphRelationshipsForEntity(investigationId, {
            entityId,
            relationshipTypes: normalizedTypes,
            direction: normalizedDirection,
            startTime,
            endTime,
          });
          return toolTextResult(JSON.stringify({ entityId, relationships }, null, 2));
        }
        case 'connected_entities': {
          if (!entityId) return toolTextResult('Error: entityId is required for connected_entities.');
          const connections = investigationService.findConnectedEntities(investigationId, {
            entityId,
            relationshipTypes: normalizedTypes,
            direction: normalizedDirection,
            startTime,
            endTime,
          });
          return toolTextResult(JSON.stringify({ entityId, connections }, null, 2));
        }
        case 'connected_within_window': {
          if (!entityId) return toolTextResult('Error: entityId is required for connected_within_window.');
          if (typeof withinMs !== 'number' || Number.isNaN(withinMs)) {
            return toolTextResult('Error: withinMs is required for connected_within_window.');
          }
          const connections = investigationService.findEntitiesConnectedWithinTimeWindow(investigationId, {
            entityId,
            withinMs,
            relationshipTypes: normalizedTypes,
            direction: normalizedDirection,
            anchorTimestamp,
          });
          return toolTextResult(JSON.stringify({ entityId, withinMs, connections }, null, 2));
        }
        case 'evidence_for_relationship': {
          if (!relationshipId) return toolTextResult('Error: relationshipId is required for evidence_for_relationship.');
          const evidence = investigationService.getEvidenceForGraphRelationship(investigationId, relationshipId);
          return toolTextResult(JSON.stringify({ relationshipId, evidence }, null, 2));
        }
        default:
          return toolTextResult(`Error: unknown queryType "${queryType}".`);
      }
    },
  };
}

export class InvestigationGraphExtension implements AgentRuntimeExtension {
  readonly name = 'investigation-graph';

  constructor(
    private readonly investigationService: InvestigationService,
    private readonly sessionLookup: (sessionId: string) => string | null
  ) {}

  async beforeSessionRun(context: BeforeSessionRunContext): Promise<BeforeSessionRunResult> {
    const investigationId = this.sessionLookup(context.session.id);
    if (!investigationId) {
      return { customTools: [] };
    }
    return {
      promptPrefix: buildPromptPrefix(),
      customTools: [createGraphQueryTool(this.investigationService, this.sessionLookup)],
    };
  }
}
