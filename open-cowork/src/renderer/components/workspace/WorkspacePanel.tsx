import { forwardRef, type ReactNode } from 'react';

export interface WorkspacePanelProps {
  title: ReactNode;
  subtitle?: ReactNode;
  icon?: ReactNode;
  actions?: ReactNode;
  density?: 'comfortable' | 'compact';
  className?: string;
  bodyClassName?: string;
  scroll?: boolean;
  footer?: ReactNode;
  children: ReactNode;
  style?: React.CSSProperties;
}

export const WorkspacePanel = forwardRef<HTMLDivElement, WorkspacePanelProps>(
  function WorkspacePanel(props, ref) {
    const {
      title,
      subtitle,
      icon,
      actions,
      density = 'comfortable',
      className = '',
      bodyClassName = '',
      scroll = true,
      footer,
      children,
      style,
    } = props;

    const headerPad = density === 'compact' ? 'px-3 py-2' : 'px-3.5 py-2.5';
    const bodyPad = density === 'compact' ? 'p-3' : 'p-3.5';

    return (
      <div
        ref={ref}
        className={`flex flex-col rounded-2xl border overflow-hidden ${className}`}
        style={{
          background: 'var(--soc-surface-card)',
          borderColor: 'var(--soc-border-default)',
          ...style,
        }}
      >
        <div
          className={`flex items-center gap-2 border-b ${headerPad}`}
          style={{ borderColor: 'var(--soc-border-subtle)' }}
        >
          {icon && (
            <div
              className="flex items-center justify-center w-6 h-6 rounded-md shrink-0"
              style={{ background: 'var(--soc-surface-elevated)', color: 'var(--soc-text-secondary)' }}
            >
              {icon}
            </div>
          )}
          <div className="min-w-0 flex-1">
            <div
              className="text-[12px] font-semibold uppercase tracking-[0.06em] truncate"
              style={{ color: 'var(--soc-text-secondary)' }}
            >
              {title}
            </div>
            {subtitle && (
              <div
                className="text-[11px] truncate"
                style={{ color: 'var(--soc-text-muted)' }}
              >
                {subtitle}
              </div>
            )}
          </div>
          {actions && <div className="flex items-center gap-1 shrink-0">{actions}</div>}
        </div>
        <div
          className={`flex-1 min-h-0 ${bodyPad} ${bodyClassName} ${
            scroll ? 'overflow-y-auto overflow-x-hidden' : 'overflow-hidden'
          }`}
        >
          {children}
        </div>
        {footer && (
          <div
            className="border-t px-3 py-2"
            style={{ borderColor: 'var(--soc-border-subtle)' }}
          >
            {footer}
          </div>
        )}
      </div>
    );
  }
);
