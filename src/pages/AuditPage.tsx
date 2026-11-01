import React, { useState, useEffect, useCallback } from 'react';
import {
  FileCode2,
  ShieldCheck,
  ShieldAlert,
  Link2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Flame,
  Undo2,
  Copy,
  Check,
  HelpCircle,
  ArrowRight,
} from 'lucide-react';
import { AuditLogEntry, ChainVerificationResult } from '../types';
import { useAuth } from '../context/AuthContext';
import { NavPage } from '../components/Sidebar';

interface AuditPageProps {
  onNavigate: (page: NavPage, evidenceId?: string) => void;
}

export const AuditPage: React.FC<AuditPageProps> = ({ onNavigate }) => {
  const { token, hasRole } = useAuth();
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isVerifyingChain, setIsVerifyingChain] = useState<boolean>(false);
  const [verificationResult, setVerificationResult] = useState<ChainVerificationResult | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Tamper Simulation State
  const [simulatingTamper, setSimulatingTamper] = useState<boolean>(false);
  const [tamperedSeq, setTamperedSeq] = useState<number | null>(null);

  const fetchLogs = useCallback(async () => {
    if (!token) return;
    try {
      setIsLoading(true);
      const res = await fetch('/api/audit/logs?limit=100', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error('Failed to load audit trail');
      const data = await res.json();
      setLogs(data.logs);
      setTotalCount(data.total);
    } catch (err) {
      console.error('Audit fetch error:', err);
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  const handleVerifyChain = async () => {
    if (!token) return;
    try {
      setIsVerifyingChain(true);
      const res = await fetch('/api/audit/verify-chain', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      setVerificationResult(data);
      if (data.isValid) {
        setNotification({
          type: 'success',
          message: `Cryptographic audit chain fully verified! ${data.totalEntries} linked nodes validated from Genesis block with 0 broken linkages.`,
        });
      } else {
        setNotification({
          type: 'error',
          message: `CHAIN INTEGRITY FAILURE: Discrepancy detected at Sequence #${data.brokenAtSequence}! ${data.reason}`,
        });
      }
      fetchLogs();
    } catch (err: unknown) {
      setNotification({
        type: 'error',
        message: err instanceof Error ? err.message : 'Chain verification failed',
      });
    } finally {
      setIsVerifyingChain(false);
    }
  };

  const handleTamperSimulation = async (action: 'tamper' | 'restore', seq?: number) => {
    if (!token) return;
    try {
      setSimulatingTamper(true);
      const targetSeq = seq || (logs.length > 0 ? logs[0].sequence_num : 1);
      const res = await fetch('/api/audit/tamper-demo', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ action, sequence_num: targetSeq }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Tamper simulation failed');

      if (action === 'tamper') {
        setTamperedSeq(targetSeq);
        setNotification({
          type: 'error',
          message: data.message,
        });
      } else {
        setTamperedSeq(null);
        setNotification({
          type: 'success',
          message: data.message,
        });
      }

      fetchLogs();
    } catch (err: unknown) {
      setNotification({
        type: 'error',
        message: err instanceof Error ? err.message : 'Simulation failed',
      });
    } finally {
      setSimulatingTamper(false);
    }
  };

  const copyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Verification Controls */}
      <div className="p-6 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Link2 className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold uppercase tracking-wider text-slate-100 font-mono">
              Tamper-Evident Cryptographic Audit Chain
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Every system transaction, login, ingestion, and verification is hashed and linked to the preceding entry:
            <code className="text-cyan-400 font-mono ml-1">Current_Hash = SHA256(Prev_Hash || Event_ID || Action || Actor || Canonical_Payload)</code>.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleVerifyChain}
            disabled={isVerifyingChain}
            className="px-4 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-xs shadow-[0_0_20px_rgba(6,182,212,0.25)] flex items-center gap-2 transition disabled:opacity-50"
          >
            <ShieldCheck className={`w-4 h-4 ${isVerifyingChain ? 'animate-spin' : ''}`} />
            <span>{isVerifyingChain ? 'Auditing Hash Chain...' : 'Verify Full Audit Chain'}</span>
          </button>
        </div>
      </div>

      {/* Notifications */}
      {notification && (
        <div
          className={`p-4 rounded-xl border flex items-center justify-between transition-all ${
            notification.type === 'success'
              ? 'bg-emerald-950/80 border-emerald-700/80 text-emerald-200'
              : 'bg-red-950/80 border-red-700/80 text-red-200'
          }`}
        >
          <div className="flex items-center gap-3">
            {notification.type === 'success' ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
            )}
            <p className="text-xs font-semibold">{notification.message}</p>
          </div>
          <button
            onClick={() => setNotification(null)}
            className="text-xs opacity-75 hover:opacity-100 font-bold px-2 py-1"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Verification Result Card if executed */}
      {verificationResult && (
        <div
          className={`p-6 rounded-xl border space-y-4 ${
            verificationResult.isValid
              ? 'bg-[#0b0f19] border-emerald-800/80 shadow-[0_0_20px_rgba(16,185,129,0.1)]'
              : 'bg-red-950/50 border-red-700 shadow-[0_0_25px_rgba(239,68,68,0.2)]'
          }`}
        >
          <div className="flex items-start justify-between pb-3 border-b border-slate-800/80">
            <div className="flex items-center gap-3">
              {verificationResult.isValid ? (
                <div className="p-2 rounded-lg bg-emerald-950 text-emerald-400 border border-emerald-700">
                  <CheckCircle2 className="w-6 h-6" />
                </div>
              ) : (
                <div className="p-2 rounded-lg bg-red-950 text-red-400 border border-red-700 animate-pulse">
                  <ShieldAlert className="w-6 h-6" />
                </div>
              )}
              <div>
                <h3 className="font-bold text-sm text-slate-100 font-mono">
                  {verificationResult.isValid
                    ? 'CHAIN INTEGRITY AUDIT: 100% CRYPTOGRAPHIC CONTINUITY VERIFIED'
                    : 'SECURITY INCIDENT: CHAIN INTEGRITY BREACH DETECTED'}
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Inspected {verificationResult.totalEntries} entries starting from Genesis Hash.
                </p>
              </div>
            </div>

            <span
              className={`text-xs font-mono font-bold uppercase px-2.5 py-1 rounded border ${
                verificationResult.isValid
                  ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
                  : 'bg-red-950 text-red-300 border-red-700'
              }`}
            >
              {verificationResult.isValid ? 'PASSED' : 'BREACH DETECTED'}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] text-slate-400 uppercase font-mono block">Genesis Anchor</span>
              <span className="text-slate-300 font-mono text-[11px] truncate block">
                {verificationResult.genesisHash.slice(0, 24)}...
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] text-slate-400 uppercase font-mono block">Tip Block Digest</span>
              <span className="text-cyan-400 font-mono text-[11px] truncate block">
                {verificationResult.tipHash ? `${verificationResult.tipHash.slice(0, 24)}...` : 'N/A'}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-[10px] text-slate-400 uppercase font-mono block">Verified Node Count</span>
              <span className="text-slate-100 font-mono font-bold">
                {verificationResult.verifiedCount} / {verificationResult.totalEntries} Nodes Intact
              </span>
            </div>
          </div>

          {!verificationResult.isValid && (
            <div className="p-4 rounded-lg bg-red-950/80 border border-red-800 text-red-200 text-xs space-y-1">
              <p className="font-bold flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                <span>Discrepancy Details (Sequence #{verificationResult.brokenAtSequence})</span>
              </p>
              <p className="text-red-300/90 font-mono text-[11px]">{verificationResult.reason}</p>
            </div>
          )}

          {/* Educational Explanation Box */}
          <div className="p-4 rounded-lg bg-slate-900/40 border border-slate-800 text-xs text-slate-400 space-y-1 leading-relaxed">
            <div className="font-semibold text-slate-300 flex items-center gap-1.5 font-mono text-[11px]">
              <HelpCircle className="w-3.5 h-3.5 text-cyan-400" />
              <span>Forensic Security Principle: Tamper-Evident vs Immutable</span>
            </div>
            <p>{verificationResult.educationalExplanation}</p>
          </div>
        </div>
      )}

      {/* Educational Tamper Simulation Console (Admin only) */}
      {hasRole('Administrator') && (
        <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
          <div>
            <div className="flex items-center gap-1.5 text-amber-400 font-bold font-mono">
              <Flame className="w-4 h-4" />
              <span>COLLEGE DEMO: AUDIT RECORD TAMPER SIMULATOR</span>
            </div>
            <p className="text-slate-400 text-[11px] mt-0.5">
              Simulate an unauthorized attacker with database access altering an audit record without updating its cryptographic hash.
            </p>
          </div>

          <div className="flex items-center gap-2">
            {tamperedSeq ? (
              <button
                onClick={() => handleTamperSimulation('restore')}
                disabled={simulatingTamper}
                className="px-3 py-1.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700 hover:bg-emerald-900 font-semibold text-xs flex items-center gap-1.5"
              >
                <Undo2 className="w-3.5 h-3.5" />
                <span>Restore Canonical Chain</span>
              </button>
            ) : (
              <button
                onClick={() => handleTamperSimulation('tamper')}
                disabled={simulatingTamper || logs.length === 0}
                className="px-3 py-1.5 rounded bg-red-950 text-red-300 border border-red-800 hover:bg-red-900 font-semibold text-xs flex items-center gap-1.5"
              >
                <Flame className="w-3.5 h-3.5 text-red-400" />
                <span>Inject Direct Row Tamper</span>
              </button>
            )}
          </div>
        </div>
      )}

      {/* Audit Log Table */}
      <div className="p-5 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2">
            <FileCode2 className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
              Audit Block Explorer ({totalCount} entries)
            </h3>
          </div>
          <button
            onClick={fetchLogs}
            disabled={isLoading}
            className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-cyan-400 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>

        {logs.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-xs">
            No audit records found.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800/80 text-slate-400">
                  <th className="pb-2.5 font-semibold">SEQ #</th>
                  <th className="pb-2.5 font-semibold">TIMESTAMP (UTC)</th>
                  <th className="pb-2.5 font-semibold">ACTION</th>
                  <th className="pb-2.5 font-semibold">ACTOR</th>
                  <th className="pb-2.5 font-semibold">PREVIOUS NODE HASH</th>
                  <th className="pb-2.5 font-semibold">CURRENT NODE HASH</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {logs.map((log) => {
                  const isTamperedRow = tamperedSeq === log.sequence_num;
                  return (
                    <tr
                      key={log.event_id}
                      className={`hover:bg-slate-900/40 transition ${
                        isTamperedRow ? 'bg-red-950/40 border-l-2 border-red-500' : ''
                      }`}
                    >
                      <td className="py-3 pr-3 text-cyan-400 font-bold">#{log.sequence_num}</td>
                      <td className="py-3 pr-3 text-slate-400 text-[11px]">{log.timestamp_utc}</td>
                      <td className="py-3 pr-3">
                        <span
                          className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold uppercase border ${
                            isTamperedRow
                              ? 'bg-red-950 text-red-400 border-red-700 animate-pulse'
                              : 'bg-slate-900 text-slate-200 border-slate-800'
                          }`}
                        >
                          {log.action}
                        </span>
                        {log.evidence_id && (
                          <div className="text-[10px] text-cyan-400 mt-0.5 font-semibold">
                            Ref: {log.evidence_id}
                          </div>
                        )}
                      </td>
                      <td className="py-3 pr-3 text-slate-300">
                        <div>{log.actor_name}</div>
                        <div className="text-[10px] text-slate-500">{log.actor_role}</div>
                      </td>
                      <td className="py-3 pr-3 text-[11px] text-slate-400 truncate max-w-[140px]">
                        <span title={log.prev_entry_hash}>{log.prev_entry_hash.slice(0, 16)}...</span>
                      </td>
                      <td className="py-3 text-[11px] text-emerald-400 font-semibold truncate max-w-[140px]">
                        <div className="flex items-center gap-1">
                          <span title={log.current_entry_hash}>{log.current_entry_hash.slice(0, 16)}...</span>
                          <button
                            onClick={() => copyHash(log.current_entry_hash)}
                            className="p-0.5 text-slate-500 hover:text-cyan-400"
                            title="Copy full node hash"
                          >
                            {copiedHash === log.current_entry_hash ? (
                              <Check className="w-2.5 h-2.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-2.5 h-2.5" />
                            )}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
