import React, { useState } from 'react';
import { ShieldCheck, Lock, User as UserIcon, AlertTriangle, ArrowRight, KeyRound, ShieldAlert } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const LoginPage: React.FC = () => {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const [expiredNotice, setExpiredNotice] = useState<string | null>(() => {
    return sessionStorage.getItem('deiv_expired_notice');
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError('Please provide both username and password.');
      return;
    }

    setIsSubmitting(true);
    setError(null);
    setExpiredNotice(null);

    const result = await login(username, password);
    if (!result.success) {
      setError(result.error || 'Access denied: invalid credentials.');
    }
    setIsSubmitting(false);
  };

  const handleQuickFill = (u: string, p: string) => {
    setUsername(u);
    setPassword(p);
    setError(null);
  };

  return (
    <div className="min-h-screen bg-[#060911] text-slate-100 flex flex-col justify-center items-center p-4 relative overflow-hidden">
      {/* Background cyber grid & glow effects */}
      <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-25"></div>
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-cyan-600/10 rounded-full blur-3xl pointer-events-none"></div>

      <div className="w-full max-w-md relative z-10">
        {/* Terminal Header */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-500/20 via-slate-900 to-blue-900/40 border border-cyan-500/40 mb-3 shadow-[0_0_25px_rgba(6,182,212,0.2)]">
            <ShieldCheck className="w-8 h-8 text-cyan-400" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 font-mono">
            DEIV TERMINAL
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
            Digital Evidence Integrity Vault & Forensic Custody System
          </p>
        </div>

        {/* Login Card */}
        <div className="bg-[#0b0f19]/95 border border-slate-800/90 rounded-xl p-6 shadow-2xl backdrop-blur-md">
          <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800/80">
            <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5" />
              AUTHENTICATION GATEWAY
            </span>
            <span className="text-[10px] font-mono text-slate-500">PORT 3000 // TLS/PROXIED</span>
          </div>

          {expiredNotice && (
            <div className="mb-4 p-3.5 rounded-lg bg-amber-950/70 border border-amber-600/80 text-amber-200 text-xs flex items-start gap-2.5 shadow-lg animate-in fade-in">
              <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-bold text-amber-300">Session Expired</p>
                <p className="text-amber-200/90">{expiredNotice}</p>
              </div>
            </div>
          )}

          {error && (
            <div className="mb-4 p-3 rounded-lg bg-red-950/60 border border-red-800/60 text-red-300 text-xs flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">Security Alert</p>
                <p className="text-red-300/90">{error}</p>
              </div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                Operator Username
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                  <UserIcon className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="e.g. admin or investigator"
                  className="w-full pl-9 pr-3 py-2 bg-slate-900/90 border border-slate-700/80 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition font-mono"
                  autoComplete="username"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                Cryptographic Passphrase
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                  <KeyRound className="w-4 h-4" />
                </div>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-9 pr-3 py-2 bg-slate-900/90 border border-slate-700/80 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition font-mono"
                  autoComplete="current-password"
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-2.5 px-4 rounded-lg bg-gradient-to-r from-cyan-600 via-cyan-500 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-sm shadow-[0_0_20px_rgba(6,182,212,0.3)] transition flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {isSubmitting ? (
                <span>Verifying Cryptographic Scrypt Salt...</span>
              ) : (
                <>
                  <span>Sign In to Vault</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Quick-fill section for project evaluation */}
          <div className="mt-6 pt-5 border-t border-slate-800/80">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                Demo Accounts (Project Grading)
              </span>
              <span className="text-[10px] text-cyan-400 font-mono">1-Click Sign-in</span>
            </div>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => handleQuickFill('admin', 'Admin@DEIV2026!')}
                className="p-2 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-purple-900/40 hover:border-purple-500/60 text-left transition group"
              >
                <div className="text-[11px] font-bold text-purple-300">Admin</div>
                <div className="text-[10px] text-slate-400 font-mono">Full Access</div>
              </button>

              <button
                type="button"
                onClick={() => handleQuickFill('investigator', 'Investigator@DEIV2026!')}
                className="p-2 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-cyan-900/40 hover:border-cyan-500/60 text-left transition group"
              >
                <div className="text-[11px] font-bold text-cyan-300">Investigator</div>
                <div className="text-[10px] text-slate-400 font-mono">Ingest & Verify</div>
              </button>

              <button
                type="button"
                onClick={() => handleQuickFill('auditor', 'Auditor@DEIV2026!')}
                className="p-2 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-amber-900/40 hover:border-amber-500/60 text-left transition group"
              >
                <div className="text-[11px] font-bold text-amber-300">Auditor</div>
                <div className="text-[10px] text-slate-400 font-mono">Read & Audit</div>
              </button>
            </div>
          </div>
        </div>

        {/* Security disclaimer footer */}
        <div className="text-center mt-5 text-[11px] text-slate-500 space-y-1">
          <p className="flex items-center justify-center gap-1">
            <ShieldAlert className="w-3.5 h-3.5 text-slate-400" />
            <span>Fundamentals of Information Security • College Term Project</span>
          </p>
          <p className="font-mono text-[10px] text-slate-600">
            SHA-256 Bitstream Integrity • Tamper-Evident Hash Chains • Role-Based Access Control
          </p>
        </div>
      </div>
    </div>
  );
};
