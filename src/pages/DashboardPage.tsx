import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Database,
  History,
  FileCheck2,
  AlertTriangle,
  ArrowRight,
  Fingerprint,
  Link2,
  CheckCircle2,
  XCircle,
  ExternalLink,
  RefreshCw,
  Search,
} from 'lucide-react';
import { DashboardMetrics, Evidence } from '../types';
import { useAuth } from '../context/AuthContext';
import { NavPage } from '../components/Sidebar';

interface DashboardPageProps {
  onNavigate: (page: NavPage, evidenceId?: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onNavigate }) => {
  const { token } = useAuth();
  const [data, setData] = useState<DashboardMetrics | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchDashboard = useCallback(async () => {
    if (!token) return;
    try {
      setIsLoading(true);
      setError(null);
      const res = await fetch('/api/stats/dashboard', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error('Failed to load dashboard metrics');
      const json = await res.json();
      setData(json);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  if (isLoading && !data) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-slate-400">
        <RefreshCw className="w-8 h-8 animate-spin text-cyan-400 mb-3" />
        <p className="text-sm font-mono">CALCULATING FORENSIC SYSTEM METRICS...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="p-6 rounded-xl bg-red-950/40 border border-red-800 text-red-200">
        <div className="flex items-center gap-2 mb-2 font-bold text-base">
          <AlertTriangle className="w-5 h-5 text-red-400" />
          <span>Dashboard Communication Error</span>
        </div>
        <p className="text-sm text-red-300">{error || 'Unable to retrieve dashboard state'}</p>
        <button
          onClick={fetchDashboard}
          className="mt-4 px-3 py-1.5 bg-red-900/60 hover:bg-red-800 text-white rounded text-xs font-semibold"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  const { metrics, chainHealth, recentEvidence, recentCustody } = data;

  return (
    <div className="space-y-6">
      {/* Top Banner Alert if Tamper Detected */}
      {metrics.tamperedCount > 0 && (
        <div className="p-4 rounded-xl bg-red-950/80 border border-red-600/80 text-red-200 shadow-[0_0_25px_rgba(239,68,68,0.2)] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-red-900/80 text-red-400">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h3 className="font-bold text-sm text-white flex items-center gap-2">
                <span>SECURITY INCIDENT: FORENSIC INTEGRITY MISMATCH DETECTED</span>
                <span className="px-2 py-0.5 rounded bg-red-800 text-[10px] font-mono font-bold uppercase">
                  {metrics.tamperedCount} Corrupted File(s)
                </span>
              </h3>
              <p className="text-xs text-red-300 mt-0.5">
                Physical disk bytes deviate from recorded SHA-256 digests. Download has been gated and blocked on affected files.
              </p>
            </div>
          </div>
          <button
            onClick={() => onNavigate('vault')}
            className="px-3 py-1.5 rounded-lg bg-red-800 hover:bg-red-700 text-white text-xs font-semibold whitespace-nowrap transition"
          >
            Inspect Vault
          </button>
        </div>
      )}

      {/* Primary KPI Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Total Evidence */}
        <div className="p-5 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm relative overflow-hidden group">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Total Evidence</span>
            <div className="p-2 rounded-lg bg-blue-950/60 border border-blue-800/40 text-blue-400">
              <Database className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-bold font-mono text-slate-100">{metrics.totalEvidence}</div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Active Forensic Custody</span>
            <span className="text-cyan-400 font-mono">Private Vault</span>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-blue-500 to-cyan-500 opacity-60"></div>
        </div>

        {/* Metric 2: Verified Matches */}
        <div className="p-5 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm relative overflow-hidden group">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Integrity Matches</span>
            <div className="p-2 rounded-lg bg-emerald-950/60 border border-emerald-800/40 text-emerald-400">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-bold font-mono text-emerald-400">{metrics.verifiedCount}</div>
          <div className="mt-2 text-[11px] text-emerald-300/80 flex items-center justify-between">
            <span>Byte-stream SHA-256 Valid</span>
            <span className="font-mono">100% Match</span>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-emerald-500 to-teal-500 opacity-60"></div>
        </div>

        {/* Metric 3: Integrity Failures */}
        <div className="p-5 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm relative overflow-hidden group">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Integrity Failures</span>
            <div className={`p-2 rounded-lg border ${metrics.tamperedCount > 0 ? 'bg-red-950 text-red-400 border-red-800' : 'bg-slate-900 text-slate-500 border-slate-800'}`}>
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className={`text-3xl font-bold font-mono ${metrics.tamperedCount > 0 ? 'text-red-400' : 'text-slate-300'}`}>
            {metrics.tamperedCount}
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Tamper Alerts</span>
            <span className={`font-mono ${metrics.tamperedCount > 0 ? 'text-red-400 font-bold' : 'text-slate-500'}`}>
              {metrics.tamperedCount > 0 ? 'GATE LOCKED' : '0 Anomalies'}
            </span>
          </div>
          <div className={`absolute bottom-0 left-0 right-0 h-0.5 ${metrics.tamperedCount > 0 ? 'bg-red-500' : 'bg-slate-700'}`}></div>
        </div>

        {/* Metric 4: Audit Chain Status */}
        <div className="p-5 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm relative overflow-hidden group">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Audit Chain Health</span>
            <div className={`p-2 rounded-lg border ${chainHealth.isValid ? 'bg-cyan-950/60 border-cyan-800/40 text-cyan-400' : 'bg-red-950 border-red-800 text-red-400'}`}>
              <Link2 className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className={`text-xl font-bold font-mono ${chainHealth.isValid ? 'text-cyan-400' : 'text-red-400'}`}>
              {chainHealth.isValid ? 'CHAIN INTACT' : 'CHAIN COMPROMISED'}
            </div>
          </div>
          <div className="mt-2 text-[11px] text-slate-400 flex items-center justify-between">
            <span>{chainHealth.totalEntries} Chained Nodes</span>
            <button
              onClick={() => onNavigate('audit')}
              className="text-cyan-400 hover:text-cyan-300 font-medium inline-flex items-center gap-1"
            >
              Verify <ArrowRight className="w-3 h-3" />
            </button>
          </div>
          <div className={`absolute bottom-0 left-0 right-0 h-0.5 ${chainHealth.isValid ? 'bg-cyan-500' : 'bg-red-500'}`}></div>
        </div>
      </div>

      {/* Main Section Grid: Recent Evidence & Live Custody Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Evidence Table */}
        <div className="lg:col-span-2 space-y-4">
          <div className="p-5 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800/80 mb-4">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200">
                  Recent Vault Evidence
                </h2>
              </div>
              <button
                onClick={() => onNavigate('vault')}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
              >
                <span>View Full Vault</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {recentEvidence.length === 0 ? (
              <div className="py-12 text-center text-slate-500 text-xs">
                No evidence items currently in the vault.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800/60 text-slate-400 font-mono">
                      <th className="pb-2 font-medium">EVIDENCE ID</th>
                      <th className="pb-2 font-medium">CASE ID</th>
                      <th className="pb-2 font-medium">TITLE & FILE</th>
                      <th className="pb-2 font-medium">STATUS</th>
                      <th className="pb-2 font-medium text-right">ACTION</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {recentEvidence.map((ev) => {
                      const isTampered = ev.status === 'TAMPER_DETECTED';
                      return (
                        <tr key={ev.id} className="hover:bg-slate-900/40 transition">
                          <td className="py-3 font-mono font-bold text-slate-200">{ev.id}</td>
                          <td className="py-3 font-mono text-cyan-400">{ev.case_id}</td>
                          <td className="py-3">
                            <div className="font-semibold text-slate-200 truncate max-w-[180px]">{ev.title}</div>
                            <div className="text-[11px] text-slate-400 font-mono truncate max-w-[180px]">
                              {ev.original_filename} ({(ev.file_size_bytes / 1024).toFixed(1)} KB)
                            </div>
                          </td>
                          <td className="py-3">
                            <span
                              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase border ${
                                isTampered
                                  ? 'bg-red-950/80 text-red-400 border-red-700/60 animate-pulse'
                                  : ev.status === 'VERIFIED'
                                  ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60'
                                  : 'bg-slate-800 text-slate-300 border-slate-700'
                              }`}
                            >
                              {isTampered ? <XCircle className="w-3 h-3 text-red-400" /> : <CheckCircle2 className="w-3 h-3 text-emerald-400" />}
                              {ev.status}
                            </span>
                          </td>
                          <td className="py-3 text-right">
                            <button
                              onClick={() => onNavigate('evidence-detail', ev.id)}
                              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-950 hover:text-cyan-300 text-slate-300 text-[11px] font-medium border border-slate-700/70 hover:border-cyan-600/60 transition inline-flex items-center gap-1"
                            >
                              <span>Inspect</span>
                              <ExternalLink className="w-3 h-3" />
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Educational Concept Card */}
          <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/80 text-xs text-slate-400 space-y-1.5">
            <div className="flex items-center gap-2 text-slate-200 font-bold text-xs uppercase tracking-wider font-mono">
              <Fingerprint className="w-4 h-4 text-cyan-400" />
              <span>Forensic Principle: Tamper-Evident vs Immutable</span>
            </div>
            <p className="leading-relaxed">
              In digital forensics, a local cryptographic hash chain is <strong>tamper-evident</strong>: any change in recorded bytes, sequence numbers, or timestamps mathematically breaks the subsequent hash links. However, without external immutable anchors or multi-party consensus, an attacker with full database and host write privileges could rewrite the whole chain from a compromised block forward. DEIV implements strict least-privilege RBAC, transaction-locked appending, and live bitstream recalculation to guarantee end-to-end evidence integrity.
            </p>
          </div>
        </div>

        {/* Right 1 Col: Live Chain of Custody Feed */}
        <div className="p-5 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm flex flex-col">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800/80 mb-4">
            <div className="flex items-center gap-2">
              <History className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200">
                Custody Event Feed
              </h2>
            </div>
            <button
              onClick={() => onNavigate('custody')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
            >
              <span>Full Log</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-3 flex-1 overflow-y-auto max-h-[480px] pr-1">
            {recentCustody.map((event) => {
              const isFailure = event.action.includes('FAIL') || event.action.includes('BLOCKED');
              return (
                <div
                  key={event.id}
                  className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80 text-xs space-y-1 hover:border-slate-700 transition"
                >
                  <div className="flex items-center justify-between">
                    <span
                      className={`font-mono text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                        isFailure
                          ? 'bg-red-950 text-red-400 border-red-800'
                          : 'bg-slate-800 text-cyan-300 border-slate-700'
                      }`}
                    >
                      {event.action}
                    </span>
                    <span className="text-[10px] text-slate-500 font-mono">
                      {new Date(event.timestamp_utc).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="text-slate-300 font-semibold truncate">
                    {event.case_id ? `${event.case_id} — ` : ''}
                    {event.evidence_id}
                  </div>
                  <div className="text-[11px] text-slate-400 flex items-center justify-between">
                    <span>By: {event.actor_name}</span>
                    <span className="font-mono text-slate-500">{event.actor_role}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
