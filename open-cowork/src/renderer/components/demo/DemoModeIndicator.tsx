import { useEffect, useState } from 'react';
import { Play, RotateCcw, Radio } from 'lucide-react';
import { useDemoState } from '../../store/selectors';
import { useIPC } from '../../hooks/useIPC';

/**
 * Global "● DEMO MODE" indicator — always visible while a demo scenario is
 * running so the presentation can never be mistaken for live production.
 * Also owns the Start / Restart controls.
 */
export function DemoModeIndicator() {
  const demoState = useDemoState();
  const { invoke, isElectron } = useIPC();
  const [starting, setStarting] = useState(false);

  // Hydrate the controller snapshot on mount so a reload during a demo
  // restores the indicator (and the workspace wiring).
  useEffect(() => {
    if (!isElectron || demoState) return;
    let cancelled = false;
    (async () => {
      try {
        const state = await invoke<import('../../../shared/cyber/demo-types').DemoControllerState>({
          type: 'demo.state',
          payload: {},
        });
        if (!cancelled && state && state.phase !== 'idle') {
          // Import lazily to avoid a store cycle in the hook graph.
          const { useAppStore } = await import('../../store');
          useAppStore.getState().setDemoState(state);
          if (state.investigationId) {
            useAppStore.getState().setActiveInvestigation(state.investigationId);
          }
        }
      } catch {
        // Demo mode not initialized (e.g. headless) — indicator stays hidden.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [isElectron, demoState, invoke]);

  if (!isElectron) return null;

  const running = demoState !== null && demoState.phase !== 'idle';

  const start = async () => {
    if (starting) return;
    setStarting(true);
    try {
      await invoke<{ investigationId: string }>({ type: running ? 'demo.restart' : 'demo.start', payload: {} });
    } finally {
      setStarting(false);
    }
  };

  // Idle: offer a Start button (rendered into the investigations header area
  // by parents); running: persistent pulsing indicator with restart.
  if (!running) {
    return (
      <button
        onClick={start}
        disabled={starting}
        data-testid="demo-start"
        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold transition-opacity hover:opacity-90 disabled:opacity-50"
        style={{ background: 'var(--soc-ai-border)', color: '#EDEBFF', border: '1px solid var(--soc-ai-primary)' }}
        title="Run the guided KIN demo investigation (deterministic, offline, synthetic data)"
      >
        <Play className="w-3.5 h-3.5" />
        {starting ? 'Starting…' : 'Start demo'}
      </button>
    );
  }

  return (
    <div className="inline-flex items-center gap-2">
      <span
        data-testid="demo-mode-indicator"
        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-bold tracking-wide uppercase"
        style={{
          background: 'var(--soc-ai-background)',
          color: 'var(--soc-ai-primary)',
          border: '1px solid var(--soc-ai-primary)',
        }}
        title="KIN Demo Mode — deterministic scenario, synthetic data, offline. Not a live investigation."
      >
        <Radio className="w-3.5 h-3.5 demo-pulse-dot" />
        Demo Mode
      </span>
      <button
        onClick={start}
        disabled={starting}
        data-testid="demo-restart"
        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-semibold transition-opacity hover:opacity-90 disabled:opacity-50"
        style={{ background: 'var(--soc-surface-elevated)', color: 'var(--soc-text-primary)', border: '1px solid var(--soc-border-default)' }}
        title="Archive this demo run and start a fresh one"
      >
        <RotateCcw className="w-3 h-3" />
        {starting ? 'Restarting…' : 'Restart demo'}
      </button>
    </div>
  );
}
