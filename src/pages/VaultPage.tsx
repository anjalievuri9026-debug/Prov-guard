import React, { useState, useEffect, useCallback } from 'react';
import {
  Database,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Download,
  ShieldCheck,
  FileText,
  ExternalLink,
  Flame,
  Undo2,
  RefreshCw,
  Copy,
  Check,
} from 'lucide-react';
import { Evidence, EvidenceStatus } from '../types';
import { useAuth } from '../context/AuthContext';
import { NavPage } from '../components/Sidebar';

interface VaultPageProps {
  onNavigate: (page: NavPage, evidenceId?: string) => void;
}

export const VaultPage: React.FC<VaultPageProps> = ({ onNavigate }) => {
  const { token, hasRole } = useAuth();
  const [evidenceList, setEvidenceList] = useState<Evidence[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [caseFilter, setCaseFilter] = useState<string>('');
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [tamperingId, setTamperingId] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const fetchEvidence = useCallback(async () => {
    if (!token) return;
    try {
      setIsLoading(true);
      setError(null);
      const params = new URLSearchParams();
      if (searchTerm.trim()) params.append('search', searchTerm.trim());
      if (statusFilter) params.append('status', statusFilter);
      if (caseFilter.trim()) params.append('case_id', caseFilter.trim());

      const res = await fetch(`/api/evidence?${params.toString()}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error('Failed to load evidence records');
      const data = await res.json();
      setEvidenceList(data.evidence);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
    }
  }, [token, searchTerm, statusFilter, caseFilter]);

  useEffect(() => {
    fetchEvidence();
  }, [fetchEvidence]);

  const handleVerify = async (id: string) => {
    if (!token) return;
    try {
      setVerifyingId(id);
      const res = await fetch(`/api/evidence/verify/${id}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Verification failed');

      if (data.matched) {
        setNotification({
          type: 'success',
          message: `Integrity check for ${id}: SHA-256 MATCH CONFIRMED! Stored disk bytes match ingestion digest.`,
        });
      } else {
        setNotification({
          type: 'error',
          message: `SECURITY ALERT for ${id}: INTEGRITY FAILURE DETECTED! Disk SHA-256 does not match original digest.`,
        });
      }

      fetchEvidence();
    } catch (err: unknown) {
      setNotification({
        type: 'error',
        message: err instanceof Error ? err.message : 'Verification failed',
      });
    } finally {
      setVerifyingId(null);
    }
  };

  const handleTamperToggle = async (id: string, currentlyTampered: boolean) => {
    if (!token) return;
    try {
      setTamperingId(id);
      const action = currentlyTampered ? 'restore' : 'tamper';
      const res = await fetch(`/api/evidence/tamper-demo/${id}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ action }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Operation failed');

      setNotification({
        type: currentlyTampered ? 'success' : 'error',
        message: data.message,
      });

      fetchEvidence();
    } catch (err: unknown) {
      setNotification({
        type: 'error',
        message: err instanceof Error ? err.message : 'Action failed',
      });
    } finally {
      setTamperingId(null);
    }
  };

  const handleDownload = async (id: string, filename: string) => {
    if (!token) return;
    try {
      const res = await fetch(`/api/evidence/download/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) {
        const errorJson = await res.json();
        setNotification({
          type: 'error',
          message: errorJson.error || 'Download blocked: evidence failed cryptographic integrity check!',
        });
        fetchEvidence();
        return;
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
    } catch (err: unknown) {
      setNotification({
        type: 'error',
        message: 'Download failed: ' + (err instanceof Error ? err.message : String(err)),
      });
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="space-y-6">
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

      {/* Controls Bar */}
      <div className="p-4 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
        <div className="flex-1 relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by Evidence ID, Case ID, filename, or SHA-256..."
            className="w-full pl-9 pr-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center gap-2">
          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Integrity Statuses</option>
            <option value="VERIFIED">VERIFIED</option>
            <option value="TAMPER_DETECTED">TAMPER DETECTED</option>
            <option value="UNVERIFIED">UNVERIFIED</option>
            <option value="MISSING_FILE">MISSING FILE</option>
          </select>

          {/* Refresh */}
          <button
            onClick={fetchEvidence}
            disabled={isLoading}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-cyan-400 transition"
            title="Refresh Vault List"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Evidence Table */}
      <div className="p-5 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800/80 mb-4">
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200">
              Forensic Evidence Repository ({evidenceList.length} items)
            </h2>
          </div>
          <span className="text-xs text-slate-500 font-mono">ENCRYPTED AT REST</span>
        </div>

        {evidenceList.length === 0 ? (
          <div className="py-16 text-center text-slate-500 text-xs space-y-2">
            <p>No evidence records matching the current criteria.</p>
            {hasRole('Administrator', 'Investigator') && (
              <button
                onClick={() => onNavigate('upload')}
                className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition"
              >
                Acquire New Evidence
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800/80 text-slate-400 font-mono">
                  <th className="pb-3 font-semibold">IDENTIFIERS</th>
                  <th className="pb-3 font-semibold">TITLE & FILE</th>
                  <th className="pb-3 font-semibold">RECORDED SHA-256 DIGEST</th>
                  <th className="pb-3 font-semibold">STATUS</th>
                  <th className="pb-3 font-semibold">CUSTODY</th>
                  <th className="pb-3 font-semibold text-right">OPERATIONS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {evidenceList.map((ev) => {
                  const isTampered = ev.status === 'TAMPER_DETECTED';
                  const isVerifying = verifyingId === ev.id;
                  const isTampering = tamperingId === ev.id;

                  return (
                    <tr key={ev.id} className="hover:bg-slate-900/40 transition">
                      {/* Identifiers */}
                      <td className="py-3.5 pr-4 align-top">
                        <div className="font-mono font-bold text-slate-100 flex items-center gap-1.5">
                          <span>{ev.id}</span>
                        </div>
                        <div className="font-mono text-[11px] text-cyan-400 font-semibold">{ev.case_id}</div>
                      </td>

                      {/* Title & File */}
                      <td className="py-3.5 pr-4 align-top max-w-xs">
                        <div className="font-semibold text-slate-200 truncate">{ev.title}</div>
                        <div className="text-[11px] text-slate-400 font-mono truncate">{ev.original_filename}</div>
                        <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                          {(ev.file_size_bytes / 1024).toFixed(1)} KB • {ev.mime_type}
                        </div>
                      </td>

                      {/* SHA-256 Digest */}
                      <td className="py-3.5 pr-4 align-top">
                        <div className="flex items-center gap-1.5 font-mono text-[11px] text-slate-300 bg-slate-950/70 p-1.5 rounded border border-slate-800/80 max-w-xs truncate">
                          <span className="truncate">{ev.original_sha256}</span>
                          <button
                            onClick={() => copyToClipboard(ev.original_sha256)}
                            className="p-1 hover:text-cyan-400 text-slate-500"
                            title="Copy full SHA-256 hash"
                          >
                            {copiedHash === ev.original_sha256 ? (
                              <Check className="w-3 h-3 text-emerald-400" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                        {ev.last_verified_at && (
                          <div className="text-[10px] text-slate-500 font-mono mt-1">
                            Verified: {new Date(ev.last_verified_at).toLocaleTimeString()}
                          </div>
                        )}
                      </td>

                      {/* Status */}
                      <td className="py-3.5 pr-4 align-top">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2 py-1 rounded text-[10px] font-mono font-bold uppercase border ${
                            isTampered
                              ? 'bg-red-950/90 text-red-400 border-red-700 shadow-[0_0_10px_rgba(239,68,68,0.2)] animate-pulse'
                              : ev.status === 'VERIFIED'
                              ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700/80'
                              : 'bg-slate-800 text-slate-300 border-slate-700'
                          }`}
                        >
                          {isTampered ? <XCircle className="w-3 h-3 text-red-400" /> : <CheckCircle2 className="w-3 h-3 text-emerald-400" />}
                          {ev.status}
                        </span>
                        {ev.is_tampered_demo === 1 && (
                          <div className="text-[10px] font-mono text-amber-400 mt-1 flex items-center gap-1">
                            <Flame className="w-2.5 h-2.5" />
                            <span>Byte Altered (Sim)</span>
                          </div>
                        )}
                      </td>

                      {/* Custody */}
                      <td className="py-3.5 pr-4 align-top text-[11px]">
                        <div className="text-slate-300 font-medium">{ev.uploader_name}</div>
                        <div className="text-slate-500 font-mono">{ev.uploader_role}</div>
                        <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                          {new Date(ev.created_at).toLocaleDateString()}
                        </div>
                      </td>

                      {/* Operations */}
                      <td className="py-3.5 align-top text-right space-y-1.5">
                        <div className="flex items-center justify-end gap-1.5">
                          {/* Live Verification Trigger */}
                          <button
                            onClick={() => handleVerify(ev.id)}
                            disabled={isVerifying}
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-950 hover:text-cyan-300 text-slate-300 text-[11px] font-medium border border-slate-700 hover:border-cyan-600 transition inline-flex items-center gap-1"
                            title="Recalculate SHA-256 directly from disk bytes"
                          >
                            <ShieldCheck className={`w-3 h-3 ${isVerifying ? 'animate-spin text-cyan-400' : 'text-cyan-400'}`} />
                            <span>{isVerifying ? 'Checking...' : 'Verify'}</span>
                          </button>

                          {/* Inspect Detail */}
                          <button
                            onClick={() => onNavigate('evidence-detail', ev.id)}
                            className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
                            title="Inspect Evidence & Custody Timeline"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                          </button>

                          {/* Download with integrity check */}
                          <button
                            onClick={() => handleDownload(ev.id, ev.original_filename)}
                            className={`p-1.5 rounded border transition ${
                              isTampered
                                ? 'bg-red-950/60 text-red-400 border-red-800 hover:bg-red-900 cursor-not-allowed'
                                : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
                            }`}
                            title={isTampered ? 'Download BLOCKED: Cryptographic integrity failure' : 'Download authenticated file'}
                          >
                            <Download className="w-3.5 h-3.5" />
                          </button>
                        </div>

                        {/* Educational Tamper Simulation Action (Investigator/Admin only) */}
                        {hasRole('Administrator', 'Investigator') && (
                          <div className="flex justify-end">
                            <button
                              onClick={() => handleTamperToggle(ev.id, ev.is_tampered_demo === 1)}
                              disabled={isTampering}
                              className={`text-[10px] font-mono px-2 py-0.5 rounded border inline-flex items-center gap-1 transition ${
                                ev.is_tampered_demo === 1
                                  ? 'bg-amber-950/80 text-amber-300 border-amber-600 hover:bg-amber-900'
                                  : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-red-300 hover:border-red-800'
                              }`}
                              title={
                                ev.is_tampered_demo === 1
                                  ? 'Restore pristine file from backup'
                                  : 'Educational testing: Flip 1 byte in stored file on disk to test tamper detection'
                              }
                            >
                              {ev.is_tampered_demo === 1 ? (
                                <>
                                  <Undo2 className="w-2.5 h-2.5" />
                                  <span>Restore Pristine</span>
                                </>
                              ) : (
                                <>
                                  <Flame className="w-2.5 h-2.5 text-red-400" />
                                  <span>Inject Byte Tamper</span>
                                </>
                              )}
                            </button>
                          </div>
                        )}
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
