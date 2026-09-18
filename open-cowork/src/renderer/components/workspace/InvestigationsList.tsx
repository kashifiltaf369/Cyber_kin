import { useEffect, useMemo, useState } from 'react';
import {
  ShieldHalf,
  Plus,
  X,
  Search,
  Archive,
  ChevronRight,
} from 'lucide-react';
import type { Investigation, CreateInvestigationInput } from '../../../shared/cyber/investigation-types';
import { useAppStore } from '../../store';
import { useIPC } from '../../hooks/useIPC';
import { useInvestigations } from '../../store/selectors';
import { formatRelative } from './role-meta';

export interface InvestigationsListProps {
  onSelect: (id: string) => void;
}

export function InvestigationsList({ onSelect }: InvestigationsListProps) {
  const investigations = useInvestigations();
  const { invoke } = useIPC();
  const setInvestigations = useAppStore((s) => s.setInvestigations);

  const [search, setSearch] = useState('');
  const [showArchived, setShowArchived] = useState(false);
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const list = await invoke<Investigation[]>({
        type: 'investigation.list',
        payload: {},
      });
      if (!cancelled && Array.isArray(list)) setInvestigations(list);
    })();
    return () => {
      cancelled = true;
    };
  }, [invoke, setInvestigations]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return investigations
      .filter((inv) => (showArchived ? true : inv.status !== 'ARCHIVED'))
      .filter((inv) =>
        q ? `${inv.title} ${inv.objective}`.toLowerCase().includes(q) : true
      )
      .sort((a, b) => b.updatedAt - a.createdAt);
  }, [investigations, search, showArchived]);

  return (
    <div
      className="flex-1 min-h-0 flex flex-col"
      style={{ background: 'var(--soc-bg-canvas)' }}
    >
      <div
        className="flex items-center gap-3 px-6 py-4 border-b"
        style={{
          background:
            'linear-gradient(180deg, var(--soc-bg-secondary) 0%, var(--soc-bg-primary) 100%)',
          borderColor: 'var(--soc-border-subtle)',
        }}
      >
        <div
          className="flex items-center justify-center w-10 h-10 rounded-xl"
          style={{
            background:
              'linear-gradient(135deg, var(--soc-ai-background), var(--soc-bg-tertiary))',
            border: '1px solid var(--soc-ai-border)',
            color: 'var(--soc-ai-primary)',
          }}
        >
          <ShieldHalf className="w-5 h-5" />
        </div>
        <div className="min-w-0 flex-1">
          <div
            className="text-[10px] font-semibold uppercase tracking-[0.16em]"
            style={{ color: 'var(--soc-text-muted)' }}
          >
            Investigations
          </div>
          <h1
            className="text-[18px] font-semibold leading-tight tracking-[-0.01em]"
            style={{ color: 'var(--soc-text-primary)' }}
          >
            AI security investigations
          </h1>
        </div>
        <button
          onClick={() => setCreating(true)}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold"
          style={{ background: 'var(--soc-accent-primary)', color: '#00131F' }}
        >
          <Plus className="w-3.5 h-3.5" /> New investigation
        </button>
      </div>

      <div
        className="flex items-center gap-2 px-6 py-2.5 border-b"
        style={{ borderColor: 'var(--soc-border-subtle)' }}
      >
        <div
          className="flex items-center gap-1.5 rounded-md px-2 py-1 flex-1 max-w-md"
          style={{
            background: 'var(--soc-surface-elevated)',
            border: '1px solid var(--soc-border-default)',
          }}
        >
          <Search className="w-3.5 h-3.5" style={{ color: 'var(--soc-text-muted)' }} />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter investigations…"
            className="flex-1 bg-transparent text-[12.5px] outline-none"
            style={{ color: 'var(--soc-text-primary)' }}
          />
        </div>
        <button
          onClick={() => setShowArchived((s) => !s)}
          className="inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-1 rounded-md"
          style={{
            background: showArchived ? 'var(--soc-accent-primary-muted)' : 'transparent',
            color: showArchived ? 'var(--soc-accent-primary)' : 'var(--soc-text-muted)',
            border: `1px solid ${showArchived ? 'var(--soc-accent-primary)' : 'var(--soc-border-default)'}`,
          }}
        >
          <Archive className="w-3 h-3" /> Archived
        </button>
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto px-6 py-4">
        {filtered.length === 0 ? (
          <div
            className="text-[12.5px] py-12 text-center"
            style={{ color: 'var(--soc-text-muted)' }}
          >
            No investigations yet. Start a new one to bring the AI team together.
          </div>
        ) : (
          <div
            className="grid gap-2.5"
            style={{
              gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
            }}
          >
            {filtered.map((inv) => (
              <InvestigationRow key={inv.id} investigation={inv} onOpen={() => onSelect(inv.id)} />
            ))}
          </div>
        )}
      </div>

      {creating && (
        <CreateInvestigationModal
          onClose={() => setCreating(false)}
          onCreated={(created) => {
            setCreating(false);
            onSelect(created.id);
          }}
        />
      )}
    </div>
  );
}

function InvestigationRow({
  investigation,
  onOpen,
}: {
  investigation: Investigation;
  onOpen: () => void;
}) {
  const active = useAppStore((s) => s.activeInvestigationId);
  const statusColor =
    investigation.status === 'INVESTIGATING'
      ? 'var(--soc-accent-primary)'
      : investigation.status === 'CONCLUDED'
        ? 'var(--soc-success-main)'
        : investigation.status === 'WAITING_FOR_HUMAN' || investigation.status === 'REPLANNING'
          ? 'var(--soc-warning-main)'
          : 'var(--soc-text-muted)';
  const isActive = active === investigation.id;
  return (
    <button
      onClick={onOpen}
      className="text-left rounded-xl p-3.5 flex flex-col gap-2 group"
      style={{
        background: isActive ? 'var(--soc-surface-elevated)' : 'var(--soc-surface-card)',
        border: `1px solid ${isActive ? 'var(--soc-accent-primary)' : 'var(--soc-border-subtle)'}`,
      }}
    >
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <div
            className="text-[14px] font-semibold leading-snug truncate"
            style={{ color: 'var(--soc-text-primary)' }}
          >
            {investigation.title || 'Untitled investigation'}
          </div>
          <p
            className="text-[11.5px] mt-0.5 line-clamp-2 leading-snug"
            style={{ color: 'var(--soc-text-secondary)' }}
          >
            {investigation.objective}
          </p>
        </div>
        <ChevronRight
          className="w-4 h-4 shrink-0 mt-0.5 opacity-60 group-hover:opacity-100"
          style={{ color: 'var(--soc-text-muted)' }}
        />
      </div>
      <div className="flex items-center gap-2 flex-wrap">
        <span
          className="text-[9.5px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded"
          style={{
            background: 'var(--soc-bg-tertiary)',
            color: statusColor,
          }}
        >
          {investigation.status.replace(/_/g, ' ')}
        </span>
        <span className="text-[10.5px]" style={{ color: 'var(--soc-text-muted)' }}>
          {investigation.evidence.length} evidence · {investigation.hypotheses.length} hypotheses
        </span>
        <span className="ml-auto text-[10.5px]" style={{ color: 'var(--soc-text-muted)' }}>
          {formatRelative(investigation.updatedAt)}
        </span>
      </div>
    </button>
  );
}

function CreateInvestigationModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (inv: Investigation) => void;
}) {
  const { invoke } = useIPC();
  const [title, setTitle] = useState('');
  const [objective, setObjective] = useState('');
  const [context, setContext] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (!title.trim() || !objective.trim()) {
      setError('Title and objective are required.');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const payload: CreateInvestigationInput = {
        title: title.trim(),
        objective: objective.trim(),
        humanContext: context.trim() || undefined,
      };
      const created = await invoke<Investigation>({
        type: 'investigation.create',
        payload,
      });
      if (created) {
        onCreated(created);
      } else {
        setError('Failed to create investigation.');
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to create investigation.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'rgba(8, 10, 13, 0.65)' }}
      onClick={onClose}
    >
      <div
        className="w-[480px] max-w-[90vw] rounded-2xl border flex flex-col"
        style={{
          background: 'var(--soc-bg-secondary)',
          borderColor: 'var(--soc-border-default)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div
          className="flex items-center gap-2 px-4 py-3 border-b"
          style={{ borderColor: 'var(--soc-border-subtle)' }}
        >
          <ShieldHalf className="w-4 h-4" style={{ color: 'var(--soc-ai-primary)' }} />
          <div
            className="text-[13px] font-semibold"
            style={{ color: 'var(--soc-text-primary)' }}
          >
            New investigation
          </div>
          <button
            onClick={onClose}
            className="ml-auto flex items-center justify-center w-7 h-7 rounded-md"
            style={{ color: 'var(--soc-text-muted)' }}
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-4 space-y-3">
          <Field label="Title">
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Suspicious PowerShell execution on HR-WS-04"
              className="w-full rounded-md px-2 py-1.5 text-[13px] outline-none"
              style={{
                background: 'var(--soc-bg-primary)',
                border: '1px solid var(--soc-border-default)',
                color: 'var(--soc-text-primary)',
              }}
            />
          </Field>
          <Field label="Objective">
            <textarea
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              rows={3}
              placeholder="What do you need the AI team to investigate and conclude?"
              className="w-full rounded-md px-2 py-1.5 text-[13px] outline-none resize-none"
              style={{
                background: 'var(--soc-bg-primary)',
                border: '1px solid var(--soc-border-default)',
                color: 'var(--soc-text-primary)',
              }}
            />
          </Field>
          <Field label="Initial context (optional)">
            <textarea
              value={context}
              onChange={(e) => setContext(e.target.value)}
              rows={2}
              placeholder="Anything the team should know up front…"
              className="w-full rounded-md px-2 py-1.5 text-[12.5px] outline-none resize-none"
              style={{
                background: 'var(--soc-bg-primary)',
                border: '1px solid var(--soc-border-default)',
                color: 'var(--soc-text-primary)',
              }}
            />
          </Field>
          {error && (
            <div
              className="text-[11.5px] px-2 py-1 rounded"
              style={{
                background: 'var(--soc-danger-muted)',
                color: 'var(--soc-danger-main)',
              }}
            >
              {error}
            </div>
          )}
        </div>
        <div
          className="flex items-center justify-end gap-2 px-4 py-3 border-t"
          style={{ borderColor: 'var(--soc-border-subtle)' }}
        >
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded-md text-[12px] font-semibold"
            style={{
              background: 'var(--soc-bg-tertiary)',
              color: 'var(--soc-text-secondary)',
              border: '1px solid var(--soc-border-default)',
            }}
          >
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={submitting}
            className="px-3 py-1.5 rounded-md text-[12px] font-semibold disabled:opacity-40"
            style={{ background: 'var(--soc-accent-primary)', color: '#00131F' }}
          >
            {submitting ? 'Creating…' : 'Create investigation'}
          </button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block space-y-1">
      <span
        className="text-[10px] font-semibold uppercase tracking-wider"
        style={{ color: 'var(--soc-text-muted)' }}
      >
        {label}
      </span>
      {children}
    </label>
  );
}
