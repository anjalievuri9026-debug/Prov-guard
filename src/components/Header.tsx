import React, { useState, useEffect } from 'react';
import { Menu, Clock, Shield, UploadCloud, RefreshCw, AlertCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

interface HeaderProps {
  onToggleMobile: () => void;
  onQuickUpload: () => void;
  title: string;
  subtitle?: string;
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  onToggleMobile,
  onQuickUpload,
  title,
  subtitle,
  onRefresh,
  isRefreshing,
}) => {
  const { user, hasRole, simulateExpiryWarning } = useAuth();
  const [utcTime, setUtcTime] = useState<string>('');

  useEffect(() => {
    const update = () => {
      const now = new Date();
      setUtcTime(now.toUTCString().replace('GMT', 'UTC'));
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="sticky top-0 z-30 bg-[#090d16]/90 backdrop-blur border-b border-slate-800/80 px-4 lg:px-8 py-3.5 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleMobile}
          className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 lg:hidden"
          aria-label="Open menu"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div>
          <h1 className="text-lg lg:text-xl font-bold text-slate-100 flex items-center gap-2">
            <span>{title}</span>
          </h1>
          {subtitle && <p className="text-xs text-slate-400">{subtitle}</p>}
        </div>
      </div>

      <div className="flex items-center gap-3">
        {/* UTC Clock */}
        <div className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-900/80 border border-slate-800 text-[11px] font-mono text-cyan-400/90">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span>{utcTime || 'UTC CLOCK SYNCING...'}</span>
        </div>

        {/* Test Expiry Warning Button */}
        <button
          onClick={simulateExpiryWarning}
          className="hidden md:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900/90 border border-amber-900/50 hover:border-amber-600/70 text-amber-300 hover:text-amber-200 text-[11px] font-mono transition"
          title="Educational demo tool: simulate approaching session expiration to test the auto-logout warning modal and session extension"
        >
          <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
          <span>Test Expiry Warning</span>
        </button>

        {/* Refresh button */}
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-cyan-400 transition"
            title="Refresh Vault State"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        )}

        {/* Ingest Action Button */}
        {hasRole('Administrator', 'Investigator') && (
          <button
            onClick={onQuickUpload}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-[0_0_15px_rgba(6,182,212,0.25)] transition"
          >
            <UploadCloud className="w-4 h-4" />
            <span className="hidden md:inline">Acquire Evidence</span>
          </button>
        )}
      </div>
    </header>
  );
};
