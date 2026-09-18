import { useMemo } from 'react';
import { Share2 } from 'lucide-react';
import type {
  Investigation,
  InvestigationEntity,
  InvestigationGraphRelationship,
} from '../../../shared/cyber/investigation-types';
import { WorkspacePanel } from './WorkspacePanel';
import { entityIcon } from './role-meta';

export interface EvidenceGraphProps {
  investigation: Investigation;
}

interface PositionedNode {
  entity: InvestigationEntity;
  x: number;
  y: number;
}

export function EvidenceGraph({ investigation }: EvidenceGraphProps) {
  const { nodes, edges, viewBox } = useMemo(() => {
    const entities: InvestigationEntity[] = investigation.entities ?? [];
    const rels: InvestigationGraphRelationship[] = investigation.graph?.relationships ?? [];

    const W = 360;
    const H = 240;
    const cx = W / 2;
    const cy = H / 2;
    const r = Math.min(W, H) / 2 - 30;

    const positioned: PositionedNode[] = entities.slice(0, 24).map((e, i) => {
      const total = Math.max(entities.length, 1);
      const angle = (i / total) * Math.PI * 2 - Math.PI / 2;
      return { entity: e, x: cx + Math.cos(angle) * r, y: cy + Math.sin(angle) * r };
    });

    const idToNode = new Map<string, PositionedNode>();
    for (const n of positioned) idToNode.set(n.entity.id, n);

    const visibleEdges = rels
      .filter((rel) => idToNode.has(rel.sourceEntityId) && idToNode.has(rel.targetEntityId))
      .slice(0, 60);

    return {
      nodes: positioned,
      edges: visibleEdges,
      viewBox: `0 0 ${W} ${H}`,
    };
  }, [investigation.entities, investigation.graph]);

  return (
    <WorkspacePanel
      title="Evidence graph"
      subtitle={
        nodes.length === 0
          ? 'No entities yet'
          : `${nodes.length} entities · ${edges.length} relationships`
      }
      icon={<Share2 className="w-3.5 h-3.5" />}
      density="compact"
      className="h-full"
    >
      {nodes.length === 0 ? (
        <div
          className="text-[12px] py-6 text-center"
          style={{ color: 'var(--soc-text-muted)' }}
        >
          The graph appears once investigators surface entities (hosts, IPs, users, files, …)
          and how they relate.
        </div>
      ) : (
        <div
          className="rounded-lg overflow-hidden"
          style={{ background: 'var(--soc-bg-primary)', border: '1px solid var(--soc-border-subtle)' }}
        >
          <svg viewBox={viewBox} className="w-full" style={{ height: 220 }}>
            <defs>
              <marker
                id="arrow"
                viewBox="0 0 10 10"
                refX="9"
                refY="5"
                markerWidth="5"
                markerHeight="5"
                orient="auto-start-reverse"
              >
                <path d="M0,0 L10,5 L0,10 z" fill="var(--soc-border-strong)" />
              </marker>
            </defs>
            {edges.map((rel) => {
              const s = nodes.find((n) => n.entity.id === rel.sourceEntityId);
              const t = nodes.find((n) => n.entity.id === rel.targetEntityId);
              if (!s || !t) return null;
              const color =
                rel.confidence >= 0.8
                  ? 'var(--soc-inv-verified)'
                  : rel.confidence >= 0.5
                    ? 'var(--soc-inv-correlated)'
                    : 'var(--soc-border-strong)';
              return (
                <g key={rel.id}>
                  <line
                    x1={s.x}
                    y1={s.y}
                    x2={t.x}
                    y2={t.y}
                    stroke={color}
                    strokeWidth={rel.confidence >= 0.7 ? 1.4 : 0.9}
                    strokeOpacity={0.7}
                    markerEnd="url(#arrow)"
                  />
                  <text
                    x={(s.x + t.x) / 2}
                    y={(s.y + t.y) / 2 - 3}
                    textAnchor="middle"
                    fontSize="8"
                    fill="var(--soc-text-muted)"
                  >
                    {rel.type.replace(/_/g, ' ').toLowerCase()}
                  </text>
                </g>
              );
            })}
            {nodes.map((n) => {
              const Icon = entityIcon(n.entity.type);
              return (
                <g key={n.entity.id} transform={`translate(${n.x}, ${n.y})`}>
                  <circle
                    r={14}
                    fill="var(--soc-surface-elevated)"
                    stroke="var(--soc-border-strong)"
                    strokeWidth={1}
                  />
                  <text textAnchor="middle" dy="3" fontSize="11" fill="var(--soc-text-secondary)">
                    {iconGlyph(Icon)}
                  </text>
                  <text
                    textAnchor="middle"
                    y={28}
                    fontSize="9"
                    fill="var(--soc-text-primary)"
                    style={{ fontWeight: 600 }}
                  >
                    {truncate(n.entity.name, 12)}
                  </text>
                  <text
                    textAnchor="middle"
                    y={38}
                    fontSize="7.5"
                    fill="var(--soc-text-muted)"
                  >
                    {n.entity.type}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
      )}
    </WorkspacePanel>
  );
}

function iconGlyph(Icon: { displayName?: string; name?: string } | undefined): string {
  const name = Icon?.displayName ?? Icon?.name ?? '';
  if (!name) return '◆';
  const m: Record<string, string> = {
    Cpu: '⌬',
    Network: '⇆',
    Globe2: '◌',
    User: '◉',
    Fingerprint: '◈',
    ScrollText: '≡',
    ShieldAlert: '⚠',
  };
  return m[name] ?? '◆';
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}
