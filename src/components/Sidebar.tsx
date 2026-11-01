import React from 'react';
import {
  ShieldCheck,
  LayoutDashboard,
  Database,
  UploadCloud,
  History,
  FileCode2,
  FileText,
  Users,
  LogOut,
  Fingerprint,
  ChevronRight,
  X,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export type NavPage =
  | 'dashboard'
  | 'vault'
  | 'upload'
  | 'custody'
  | 'audit'
  | 'reports'
  | 'users'
  | 'evidence-detail';

interface SidebarProps {
  currentPage: NavPage;
  onNavigate: (page: NavPage) => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentPage, onNavigate, mobileOpen, onCloseMobile }) => {
  const { user, logout, hasRole } = useAuth();

  const navItems = [
    {
      id: 'dashboard' as NavPage,
      label: 'Security Dashboard',
      icon: LayoutDashboard,
      roles: ['Administrator', 'Investigator', 'Auditor'],
    },
    {
      id: 'vault' as NavPage,
      label: 'Evidence Vault',
      icon: Database,
      roles: ['Administrator', 'Investigator', 'Auditor'],
    },
    {
      id: 'upload' as NavPage,
      label: 'Ingest Evidence',
      icon: UploadCloud,
      roles: ['Administrator', 'Investigator'],
    },
    {
      id: 'custody' as NavPage,
      label: 'Chain of Custody',
      icon: History,
      roles: ['Administrator', 'Investigator', 'Auditor'],
    },
    {
      id: 'audit' as NavPage,
      label: 'Tamper-Evident Audit',
      icon: FileCode2,
      roles: ['Administrator', 'Investigator', 'Auditor'],
    },
    {
      id: 'reports' as NavPage,
      label: 'Forensic PDF Reports',
      icon: FileText,
      roles: ['Administrator', 'Investigator', 'Auditor'],
    },
    {
      id: 'users' as NavPage,
      label: 'Admin User Management',
      icon: Users,
      roles: ['Administrator'],
    },
  ];

  const filteredItems = navItems.filter((item) =>
    user ? item.roles.includes(user.role) : false
  );

  const getRoleBadgeColor = (role?: string) => {
    switch (role) {
      case 'Administrator':
        return 'bg-purple-950/80 text-purple-300 border-purple-500/40';
      case 'Investigator':
        return 'bg-cyan-950/80 text-cyan-300 border-cyan-500/40';
      case 'Auditor':
        return 'bg-amber-950/80 text-amber-300 border-amber-500/40';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <>
      {/* Mobile backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm lg:hidden"
          onClick={onCloseMobile}
        />
      )}

      <aside
        className={`fixed top-0 bottom-0 left-0 z-50 w-72 bg-[#090d16] border-r border-slate-800/80 flex flex-col transition-transform duration-300 ease-in-out lg:translate-x-0 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand header */}
        <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-600/10 border border-cyan-500/40 shadow-inner">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
              <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
              </span>
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="text-base font-bold tracking-wider text-slate-100 font-mono">DEIV</span>
                <span className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-700/50">
                  Forensic
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-medium">Evidence Integrity Vault</p>
            </div>
          </div>
          <button
            onClick={onCloseMobile}
            className="p-1 rounded text-slate-400 hover:text-slate-200 lg:hidden"
            aria-label="Close navigation"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Security level badge */}
        <div className="px-5 py-3 border-b border-slate-800/60 bg-slate-900/40">
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-400 flex items-center gap-1 font-mono">
              <Fingerprint className="w-3.5 h-3.5 text-cyan-400" />
              DIGITAL FORENSICS
            </span>
            <span className="text-emerald-400 font-mono font-medium flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              SHA-256 ACTIVE
            </span>
          </div>
        </div>

        {/* Navigation list */}
        <nav className="flex-1 p-3 space-y-1.5 overflow-y-auto">
          {filteredItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentPage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  onNavigate(item.id);
                  onCloseMobile();
                }}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shadow-[0_0_15px_rgba(6,182,212,0.1)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                  <span>{item.label}</span>
                </div>
                {isActive && <ChevronRight className="w-4 h-4 text-cyan-400" />}
              </button>
            );
          })}
        </nav>

        {/* User clearance profile & logout */}
        {user && (
          <div className="p-4 border-t border-slate-800/80 bg-slate-900/50">
            <div className="flex items-center justify-between mb-2">
              <div className="truncate">
                <p className="text-xs font-semibold text-slate-200 truncate">{user.fullName}</p>
                <p className="text-[11px] font-mono text-slate-400">@{user.username}</p>
              </div>
              <span
                className={`text-[10px] font-semibold uppercase px-2 py-0.5 rounded border ${getRoleBadgeColor(
                  user.role
                )}`}
              >
                {user.role}
              </span>
            </div>
            <button
              onClick={() => logout()}
              className="w-full mt-2 flex items-center justify-center gap-2 px-3 py-1.5 rounded bg-slate-800/80 hover:bg-red-950/40 text-slate-300 hover:text-red-300 border border-slate-700/60 hover:border-red-800/60 text-xs font-medium transition"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Terminate Session</span>
            </button>
          </div>
        )}
      </aside>
    </>
  );
};
