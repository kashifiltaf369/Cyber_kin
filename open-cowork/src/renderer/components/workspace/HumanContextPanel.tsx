import { useState } from 'react';
import { Brain, Plus, ShieldAlert, AlertTriangle, Compass, Tag, FileText } from 'lucide-react';
import type { Investigation, HumanCapabilityContext } from '../../../shared/cyber/investigation-types';
import { WorkspacePanel } from './WorkspacePanel';

export interface HumanContextPanelProps {
  investigation: Investigation;
  onAddNote: (note: string) => void;
  onAddSuspicion: (suspicion: string) => void;
  onAddDirection: (direction: string) => void;
  onAddConstraint: (constraint: string) => void;
  onSetRiskTolerance: (level: HumanCapabilityContext['riskTolerance']) => void;
}

export function HumanContextPanel({
  investigation,
  onAddNote,
  onAddSuspicion,
  onAddDirection,
  onAddConstraint,
  onSetRiskTolerance,
}: HumanContextPanelProps) {
  const ctx = investigation.humanCapabilityContext;
  const [draft, setDraft] = useState<{ kind: DraftKind; value: string }>({
    kind: 'note',
    value: '',
  });

  const submit = () => {
    const v = draft.value.trim();
    if (!v) return;
    switch (draft.kind) {
      case 'note':
        onAddNote(v);
        break;
      case 'suspicion':
        onAddSuspicion(v);
        break;
      case 'direction':
        onAddDirection(v);
        break;
      case 'constraint':
        onAddConstraint(v);
        break;
    }
    setDraft((d) => ({ ...d, value: '' }));
  };

  return (
    <WorkspacePanel
      title="Human expert context"
      subtitle="Your hypotheses, suspicions, and constraints guide the AI team"
      icon={<Brain className="w-3.5 h-3.5" />}
      density="compact"
      footer={
        <div className="flex items-center gap-1.5">
          <select
            value={draft.kind}
            onChange={(e) => setDraft((d) => ({ ...d, kind: e.target.value as DraftKind }))}
            className="text-[11px] rounded-md px-1.5 py-1 outline-none"
            style={{
              background: 'var(--soc-surface-elevated)',
              border: '1px solid var(--soc-border-default)',
              color: 'var(--soc-text-secondary)',
            }}
          >
            <option value="note">Note</option>
            <option value="suspicion">Suspicion</option>
            <option value="direction">Direction</option>
            <option value="constraint">Constraint</option>
          </select>
          <input
            value={draft.value}
            onChange={(e) => setDraft((d) => ({ ...d, value: e.target.value }))}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                submit();
              }
            }}
            placeholder={
              draft.kind === 'note'
                ? 'Add a note for the AI team…'
                : draft.kind === 'suspicion'
                  ? 'What looks suspicious to you…'
                  : draft.kind === 'direction'
                    ? 'Steer the team toward…'
                    : 'Hard rule the team must respect…'
            }
            className="flex-1 text-[12px] rounded-md px-2 py-1 outline-none"
            style={{
              background: 'var(--soc-surface-elevated)',
              border: '1px solid var(--soc-border-default)',
              color: 'var(--soc-text-primary)',
            }}
          />
          <button
            onClick={submit}
            disabled={!draft.value.trim()}
            className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-semibold disabled:opacity-40"
            style={{
              background: 'var(--soc-accent-primary)',
              color: '#00131F',
            }}
          >
            <Plus className="w-3 h-3" /> Add
          </button>
        </div>
      }
    >
      <div className="flex flex-col gap-3">
        <RiskToleranceRow
          value={ctx.riskTolerance}
          onChange={onSetRiskTolerance}
        />

        {ctx.suspicions.length > 0 && (
          <Section
            icon={<AlertTriangle className="w-3 h-3" />}
            title="Suspicions"
            color="var(--soc-warning-main)"
          >
            <ChipList values={ctx.suspicions.map((s) => s.value)} />
          </Section>
        )}

        {ctx.investigationDirections.length > 0 && (
          <Section
            icon={<Compass className="w-3 h-3" />}
            title="Directions"
            color="var(--soc-info-main)"
          >
            <ChipList values={ctx.investigationDirections.map((s) => s.value)} />
          </Section>
        )}

        {ctx.constraints.length > 0 && (
          <Section
            icon={<ShieldAlert className="w-3 h-3" />}
            title="Constraints"
            color="var(--soc-danger-main)"
          >
            <ChipList values={ctx.constraints.map((s) => s.value)} />
          </Section>
        )}

        {ctx.notes.length > 0 && (
          <Section
            icon={<FileText className="w-3 h-3" />}
            title="Notes"
            color="var(--soc-text-secondary)"
          >
            <ChipList values={ctx.notes.map((s) => s.value)} />
          </Section>
        )}

        {ctx.environmentalKnowledge.length > 0 && (
          <Section
            icon={<Tag className="w-3 h-3" />}
            title="Environment knowledge"
            color="var(--soc-text-muted)"
          >
            <ChipList values={ctx.environmentalKnowledge} muted />
          </Section>
        )}

        {ctx.priorities.length > 0 && (
          <Section
            icon={<Tag className="w-3 h-3" />}
            title="Priorities"
            color="var(--soc-accent-primary)"
          >
            <ChipList values={ctx.priorities.map((p) => p.value)} />
          </Section>
        )}

        {ctx.knownLegitimateBehavior.length > 0 && (
          <Section
            icon={<Tag className="w-3 h-3" />}
            title="Known legitimate"
            color="var(--soc-success-main)"
          >
            <ChipList values={ctx.knownLegitimateBehavior.map((p) => p.value)} />
          </Section>
        )}

        {ctx.knownAbnormalBehavior.length > 0 && (
          <Section
            icon={<Tag className="w-3 h-3" />}
            title="Known abnormal"
            color="var(--soc-inv-conflicted)"
          >
            <ChipList values={ctx.knownAbnormalBehavior.map((p) => p.value)} />
          </Section>
        )}

        {empty(ctx) && (
          <div
            className="text-[12px] py-3 text-center"
            style={{ color: 'var(--soc-text-muted)' }}
          >
            No expert context yet. Add suspicions, directions, and constraints to steer the team.
          </div>
        )}
      </div>
    </WorkspacePanel>
  );
}

type DraftKind = 'note' | 'suspicion' | 'direction' | 'constraint';

function empty(ctx: HumanCapabilityContext): boolean {
  return (
    ctx.notes.length === 0 &&
    ctx.suspicions.length === 0 &&
    ctx.investigationDirections.length === 0 &&
    ctx.constraints.length === 0 &&
    ctx.environmentalKnowledge.length === 0 &&
    ctx.priorities.length === 0 &&
    ctx.knownLegitimateBehavior.length === 0 &&
    ctx.knownAbnormalBehavior.length === 0
  );
}

function Section({
  icon,
  title,
  color,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  color: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <div
        className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.06em]"
        style={{ color }}
      >
        {icon}
        {title}
      </div>
      {children}
    </div>
  );
}

function ChipList({ values, muted }: { values: string[]; muted?: boolean }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {values.map((v, i) => (
        <span
          key={`${v}-${i}`}
          className="text-[11px] leading-relaxed px-2 py-1 rounded-md"
          style={{
            background: muted ? 'var(--soc-surface-elevated)' : 'var(--soc-bg-tertiary)',
            border: '1px solid var(--soc-border-subtle)',
            color: muted ? 'var(--soc-text-muted)' : 'var(--soc-text-secondary)',
          }}
        >
          {v}
        </span>
      ))}
    </div>
  );
}

function RiskToleranceRow({
  value,
  onChange,
}: {
  value: HumanCapabilityContext['riskTolerance'];
  onChange: (v: HumanCapabilityContext['riskTolerance']) => void;
}) {
  const levels: Array<{ key: HumanCapabilityContext['riskTolerance']; label: string; color: string }> = [
    { key: 'LOW', label: 'Low', color: 'var(--soc-success-main)' },
    { key: 'MEDIUM', label: 'Medium', color: 'var(--soc-warning-main)' },
    { key: 'HIGH', label: 'High', color: 'var(--soc-danger-main)' },
  ];
  return (
    <div
      className="flex items-center justify-between rounded-lg px-2.5 py-1.5"
      style={{
        background: 'var(--soc-surface-elevated)',
        border: '1px solid var(--soc-border-subtle)',
      }}
    >
      <div className="flex items-center gap-1.5">
        <ShieldAlert className="w-3.5 h-3.5" style={{ color: 'var(--soc-text-muted)' }} />
        <span
          className="text-[11px] uppercase tracking-wider font-semibold"
          style={{ color: 'var(--soc-text-muted)' }}
        >
          Risk tolerance
        </span>
      </div>
      <div className="flex items-center gap-1">
        {levels.map((l) => {
          const active = value === l.key;
          return (
            <button
              key={l.key}
              onClick={() => onChange(l.key)}
              className="text-[11px] font-semibold px-2 py-0.5 rounded-md transition-colors"
              style={{
                background: active ? l.color : 'transparent',
                color: active ? '#0B0F14' : 'var(--soc-text-muted)',
                border: `1px solid ${active ? l.color : 'var(--soc-border-default)'}`,
              }}
            >
              {l.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}
