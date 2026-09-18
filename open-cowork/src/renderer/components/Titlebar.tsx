import { Minus, Square, X, Copy } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

const isMac = typeof window !== 'undefined' && window.electronAPI?.platform === 'darwin';

export function Titlebar() {
  const { t } = useTranslation();
  const [isMaximized, setIsMaximized] = useState(false);

  const handleMinimize = () => {
    window.electronAPI?.window.minimize();
  };

  const handleMaximize = () => {
    window.electronAPI?.window.maximize();
    setIsMaximized(!isMaximized);
  };

  const handleClose = () => {
    window.electronAPI?.window.close();
  };

  return (
    <div
      className={`h-10 bg-background-secondary border-b border-border flex items-center titlebar-drag shrink-0 ${
        isMac ? 'justify-start pl-20' : 'justify-between'
      }`}
    >
      {/* Status indicator */}
      {!isMac && (
        <div className="flex items-center gap-2 pl-3 titlebar-no-drag">
          <span className="text-[11px] font-semibold tracking-[0.08em] text-text-primary uppercase">
            KIN
          </span>
          <span className="flex items-center gap-1.5 text-[11px] text-text-secondary">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-success" />
            </span>
            Online
          </span>
        </div>
      )}

      {/* macOS branding area */}
      {isMac && (
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-semibold tracking-[0.08em] text-text-primary uppercase">
            KIN
          </span>
          <span className="flex items-center gap-1.5 text-[11px] text-text-secondary">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-success" />
            </span>
            Online
          </span>
        </div>
      )}

      {/* Window Controls (for Windows/Linux - macOS uses native traffic lights) */}
      {!isMac && (
        <div className="flex items-center titlebar-no-drag h-full">
          <button
            onClick={handleMinimize}
            className="w-12 h-full flex items-center justify-center hover:bg-surface transition-colors"
            title={t('window.minimize')}
          >
            <Minus className="w-4 h-4 text-text-secondary" />
          </button>
          <button
            onClick={handleMaximize}
            className="w-12 h-full flex items-center justify-center hover:bg-surface transition-colors"
            title={isMaximized ? t('window.restore') : t('window.maximize')}
          >
            {isMaximized ? (
              <Copy className="w-3.5 h-3.5 text-text-secondary" />
            ) : (
              <Square className="w-3.5 h-3.5 text-text-secondary" />
            )}
          </button>
          <button
            onClick={handleClose}
            className="w-12 h-full flex items-center justify-center hover:bg-red-500 transition-colors group"
            title={t('window.close')}
          >
            <X className="w-4 h-4 text-text-secondary group-hover:text-white" />
          </button>
        </div>
      )}
    </div>
  );
}
