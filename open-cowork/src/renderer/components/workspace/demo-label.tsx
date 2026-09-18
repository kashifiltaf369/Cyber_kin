import type { Investigation } from '../../../shared/cyber/investigation-types';

/**
 * Markers written by the synthetic (DEMO) environment when it seeds an
 * investigation. The renderer must never present demo data as real findings,
 * so workspace components surface a DEMO badge whenever these appear.
 *
 * Kept as literals (not imported from main-process code) so renderer bundles
 * do not pull in backend modules.
 */
const SYNTHETIC_DEMO_TITLE_PREFIX = '[SYNTHETIC DEMO]';
const SYNTHETIC_DEMO_WATERMARK = 'SYNTHETIC_DEMO_DATA';
// KIN Demo Mode (deterministic scenario controller) markers.
const DEMO_MODE_TITLE_PREFIX = '[DEMO MODE]';
const DEMO_MODE_WATERMARK = 'KIN_DEMO_MODE';

export function isSyntheticDemoInvestigation(investigation: Investigation): boolean {
  if (investigation.title.startsWith(SYNTHETIC_DEMO_TITLE_PREFIX)) return true;
  if (investigation.title.startsWith(DEMO_MODE_TITLE_PREFIX)) return true;
  if (investigation.objective.includes(SYNTHETIC_DEMO_WATERMARK)) return true;
  if (investigation.objective.includes(DEMO_MODE_WATERMARK)) return true;
  const context = investigation.humanCapabilityContext;
  if (context?.notes?.some((note) => note.value.includes(SYNTHETIC_DEMO_WATERMARK))) return true;
  if (context?.notes?.some((note) => note.value.includes(SYNTHETIC_DEMO_TITLE_PREFIX))) return true;
  if (context?.notes?.some((note) => note.value.includes(DEMO_MODE_WATERMARK))) return true;
  if (context?.notes?.some((note) => note.value.includes(DEMO_MODE_TITLE_PREFIX))) return true;
  return false;
}

export function DemoBadge() {
  return (
    <span
      className="inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-bold tracking-wide uppercase shrink-0"
      style={{
        background: 'var(--soc-warning-muted)',
        color: 'var(--soc-warning-main)',
        border: '1px solid var(--soc-warning-main)',
      }}
      title="This investigation uses synthetic demo data — never real telemetry"
    >
      Demo
    </span>
  );
}
