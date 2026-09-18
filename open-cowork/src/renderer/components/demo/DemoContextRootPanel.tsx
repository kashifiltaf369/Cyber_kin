import { CheckCircle2, Loader2, Circle, Database } from 'lucide-react';
import type { DemoControllerState } from '../../../shared/cyber/demo-types';
import { WorkspacePanel } from '../workspace/WorkspacePanel';

/**
 * Context Root for the demo scenario — mirrors the deterministic controller's
 * context sections. Each row fills in as the controller marks it ready, so
 * the panel reflects real demo-controller state (not local timers).
 */
export function DemoContextRootPanel({ demoState }: { demoState: DemoControllerState }) {
  const ready = demoState.contextRoot.filter((s) => s.status === 'ready').length;

  return (
    <div data-testid="demo-context-root" className="min-h-0">
    <WorkspacePanel
      title="Context root"
      subtitle={`${ready}/${demoState.contextRoot.length} assembled`}
      icon={<Database className="w-3.5 h-3.5" />}
      density="compact"
    >
      <ul className="space-y-1">
        {demoState.contextRoot.map((section) => (
          <li
            key={section.key}
            data-testid={`demo-context-${section.key}`}
            className="flex items-center gap-2 rounded-lg px-2 py-1.5"
            style={{
              background: section.status === 'ready' ? 'var(--soc-surface-elevated)' : 'transparent',
              border: '1px solid var(--soc-border-subtle)',
              opacity: section.status === 'pending' ? 0.55 : 1,
            }}
          >
            {section.status === 'ready' ? (
              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--soc-success-main)' }} />
            ) : section.status === 'loading' ? (
              <Loader2 className="w-3.5 h-3.5 shrink-0 animate-spin" style={{ color: 'var(--soc-ai-secondary)' }} />
            ) : (
              <Circle className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--soc-text-muted)' }} />
            )}
            <span className="text-[11.5px] font-medium shrink-0" style={{ color: 'var(--soc-text-primary)' }}>
              {section.label}
            </span>
            {section.status === 'ready' && section.detail && (
              <span className="text-[11px] truncate" style={{ color: 'var(--soc-text-muted)' }}>
                {section.detail}
              </span>
            )}
          </li>
        ))}
      </ul>
    </WorkspacePanel>
    </div>
  );
}
