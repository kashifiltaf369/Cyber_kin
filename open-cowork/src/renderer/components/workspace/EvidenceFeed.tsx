import { useMemo, useState } from 'react';
import {
  Search,
  Inbox,
  Link2,
  ChevronDown,
  ChevronRight,
  Wrench,
  User as UserIcon,
  Cpu,
  GitBranch,
  ExternalLink,
} from 'lucide-react';
import type {
  Investigation,
  InvestigationEvidence,
  InvestigationEvidenceProvenance,
} from '../../../shared/cyber/investigation-types';
import { WorkspacePanel } from './WorkspacePanel';
import {
  evidenceAccent,
  evidenceAccentVar,
  formatClock,
  formatRelative,
} from './role-meta';

export interface EvidenceFeedProps {
  investigation: Investigation;
  onSelectEvidence: (evidence: InvestigationEvidence) => void;
  selectedEvidenceId?: string | null;
}

const KIND_LABEL: Record<InvestigationEvidence['kind'], string> = {
  file: 'File',
  log_excerpt: 'Log',
  url: 'URL',
  command_output: 'Command',
  api_result: 'API',
  note: 'Note',
  image: 'Image',
  structured_record: 'Record',
  other: 'Other',
};

export function EvidenceFeed({
  investigation,
  onSelectEvidence,
  selectedEvidenceId,
}: EvidenceFeedProps) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<'all' | 'observed' | 'correlated' | 'inferred' | 'verified' | 'conflicted'>('all');
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return [...investigation.evidence]
      .sort((a, b) => b.collectedAt - a.collectedAt)
      .filter((ev) => {
        if (q) {
          const blob = `${ev.title} ${ev.summary} ${ev.content} ${ev.source} ${ev.tags.join(' ')}`.toLowerCase();
          if (!blob.includes(q)) return false;
        }
        if (filter === 'all') return true;
        return evidenceAccent(ev) === filter;
      });
  }, [investigation.evidence, query, filter]);

  return (
    <WorkspacePanel
      title="Evidence feed"
      subtitle={`${investigation.evidence.length} items · live collection`}
      icon={<Inbox className="w-3.5 h-3.5" />}
      density="compact"
      className="h-full"
      actions={
        <div className="flex items-center gap-1">
          {(['all', 'observed', 'correlated', 'inferred', 'verified', 'conflicted'] as const).map((k) => {
            const active = filter === k;
            return (
              <button
                key={k}
                onClick={() => setFilter(k)}
                className="text-[9.5px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded"
                style={{
                  background: active ? 'var(--soc-accent-primary-muted)' : 'transparent',
                  color: active ? 'var(--soc-accent-primary)' : 'var(--soc-text-muted)',
                }}
              >
                {k === 'all' ? 'All' : k}
              </button>
            );
          })}
        </div>
      }
    >
      <div className="flex flex-col gap-2 h-full">
        <div
          className="flex items-center gap-1.5 rounded-md px-2 py-1"
          style={{
            background: 'var(--soc-surface-elevated)',
            border: '1px solid var(--soc-border-default)',
          }}
        >
          <Search className="w-3 h-3" style={{ color: 'var(--soc-text-muted)' }} />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter evidence…"
            className="flex-1 bg-transparent text-[12px] outline-none"
            style={{ color: 'var(--soc-text-primary)' }}
          />
        </div>

        <div className="flex-1 min-h-0 overflow-y-auto -mx-1 px-1 space-y-1.5">
          {filtered.length === 0 && (
            <div
              className="text-[12px] py-6 text-center"
              style={{ color: 'var(--soc-text-muted)' }}
            >
              {investigation.evidence.length === 0
                ? 'No evidence yet. The AI team will collect and register evidence as they work.'
                : 'No matches for the current filter.'}
            </div>
          )}
          {filtered.map((ev) => {
            const accent = evidenceAccentVar(evidenceAccent(ev));
            const isSelected = selectedEvidenceId === ev.id;
            const isOpen = expanded[ev.id] ?? isSelected;
            return (
              <div
                key={ev.id}
                className="rounded-lg overflow-hidden"
                style={{
                  background: 'var(--soc-surface-card)',
                  border: `1px solid ${isSelected ? accent : 'var(--soc-border-subtle)'}`,
                }}
              >
                <button
                  onClick={() => {
                    setExpanded((m) => ({ ...m, [ev.id]: !(m[ev.id] ?? isSelected) }));
                    onSelectEvidence(ev);
                  }}
                  className="w-full text-left p-2.5 flex items-start gap-2"
                >
                  <div
                    className="w-1 self-stretch rounded-full shrink-0"
                    style={{ background: accent }}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span
                        className="text-[9.5px] font-semibold uppercase tracking-wider px-1 py-0.5 rounded"
                        style={{
                          background: 'var(--soc-bg-tertiary)',
                          color: accent,
                        }}
                      >
                        {KIND_LABEL[ev.kind]}
                      </span>
                      <span
                        className="text-[10px]"
                        style={{ color: 'var(--soc-text-muted)' }}
                      >
                        {formatRelative(ev.collectedAt)}
                      </span>
                      {ev.confidence > 0 && (
                        <span
                          className="ml-auto text-[10px] font-semibold"
                          style={{ color: 'var(--soc-text-muted)' }}
                          title={`Confidence ${Math.round(ev.confidence * 100)}%`}
                        >
                          {Math.round(ev.confidence * 100)}%
                        </span>
                      )}
                    </div>
                    <div
                      className="text-[12px] font-semibold mt-1 leading-snug"
                      style={{ color: 'var(--soc-text-primary)' }}
                    >
                      {ev.title}
                    </div>
                    {ev.summary && (
                      <div
                        className="text-[11.5px] mt-0.5 line-clamp-2"
                        style={{ color: 'var(--soc-text-secondary)' }}
                      >
                        {ev.summary}
                      </div>
                    )}
                    {ev.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1.5">
                        {ev.tags.slice(0, 5).map((t) => (
                          <span
                            key={t}
                            className="text-[10px] px-1.5 py-0.5 rounded"
                            style={{
                              background: 'var(--soc-surface-elevated)',
                              color: 'var(--soc-text-muted)',
                            }}
                          >
                            #{t}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="shrink-0 mt-0.5" style={{ color: 'var(--soc-text-muted)' }}>
                    {isOpen ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                  </div>
                </button>
                {isOpen && (
                  <div
                    className="px-3 py-2.5 border-t space-y-2"
                    style={{
                      borderColor: 'var(--soc-border-subtle)',
                      background: 'var(--soc-bg-primary)',
                    }}
                  >
                    <ProvenanceRow provenance={ev.provenance} />
                    {ev.content && (
                      <pre
                        className="text-[11px] font-mono leading-relaxed whitespace-pre-wrap break-words p-2 rounded max-h-48 overflow-auto"
                        style={{
                          background: 'var(--soc-bg-tertiary)',
                          color: 'var(--soc-text-secondary)',
                          border: '1px solid var(--soc-border-subtle)',
                        }}
                      >
                        {ev.content}
                      </pre>
                    )}
                    {ev.relationships.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {ev.relationships.map((rel) => (
                          <span
                            key={rel.id}
                            className="text-[10px] inline-flex items-center gap-1 px-1.5 py-0.5 rounded"
                            style={{
                              background: 'var(--soc-info-muted)',
                              color: 'var(--soc-info-main)',
                            }}
                          >
                            <Link2 className="w-2.5 h-2.5" />
                            {rel.type.replace(/_/g, ' ').toLowerCase()}
                          </span>
                        ))}
                      </div>
                    )}
                    {ev.hypothesisIds.length > 0 && (
                      <div className="flex items-center gap-1.5 text-[10px]" style={{ color: 'var(--soc-text-muted)' }}>
                        <GitBranch className="w-3 h-3" />
                        Tied to {ev.hypothesisIds.length} hypothesis
                        {ev.hypothesisIds.length === 1 ? '' : 'es'}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </WorkspacePanel>
  );
}

function ProvenanceRow({ provenance }: { provenance: InvestigationEvidenceProvenance }) {
  const Icon =
    provenance.method === 'human_reported'
      ? UserIcon
      : provenance.method === 'tool_output'
        ? Wrench
        : provenance.method === 'derived_analysis'
          ? GitBranch
          : provenance.method === 'imported'
            ? ExternalLink
            : Cpu;
  const label =
    provenance.method === 'human_reported'
      ? 'Human reported'
      : provenance.method === 'tool_output'
        ? 'Tool output'
        : provenance.method === 'derived_analysis'
          ? 'Derived'
          : provenance.method === 'imported'
            ? 'Imported'
            : 'Agent observed';
  return (
    <div
      className="flex items-start gap-2 p-2 rounded text-[11px]"
      style={{
        background: 'var(--soc-surface-elevated)',
        border: '1px solid var(--soc-border-subtle)',
      }}
    >
      <div
        className="flex items-center justify-center w-5 h-5 rounded shrink-0 mt-0.5"
        style={{ background: 'var(--soc-bg-tertiary)', color: 'var(--soc-text-secondary)' }}
      >
        <Icon className="w-3 h-3" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span
            className="text-[10px] font-semibold uppercase tracking-wider"
            style={{ color: 'var(--soc-text-secondary)' }}
          >
            {label}
          </span>
          <span className="text-[10px]" style={{ color: 'var(--soc-text-muted)' }}>
            · {provenance.sourceType.replace(/_/g, ' ')}
          </span>
          {provenance.sourceLabel && (
            <span className="text-[10px] truncate" style={{ color: 'var(--soc-text-muted)' }}>
              · {provenance.sourceLabel}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 mt-0.5 text-[10px]" style={{ color: 'var(--soc-text-muted)' }}>
          {provenance.collectedBy && <span>by {provenance.collectedBy}</span>}
          {provenance.adapter && <span>via {provenance.adapter}</span>}
          {provenance.capability && <span>· {provenance.capability}</span>}
          <span className="ml-auto font-mono">{formatClock(Date.now())}</span>
        </div>
      </div>
    </div>
  );
}
