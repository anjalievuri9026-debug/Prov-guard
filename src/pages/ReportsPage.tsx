import React, { useState, useEffect, useCallback } from 'react';
import {
  FileText,
  Download,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Search,
  ExternalLink,
  FileCheck2,
} from 'lucide-react';
import { Evidence } from '../types';
import { useAuth } from '../context/AuthContext';
import { NavPage } from '../components/Sidebar';

interface ReportsPageProps {
  onNavigate: (page: NavPage, evidenceId?: string) => void;
}

export const ReportsPage: React.FC<ReportsPageProps> = ({ onNavigate }) => {
  const { token } = useAuth();
  const [evidenceList, setEvidenceList] = useState<Evidence[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const fetchEvidence = useCallback(async () => {
    if (!token) return;
    try {
      setIsLoading(true);
      const res = await fetch('/api/evidence', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error('Failed to load evidence');
      const data = await res.json();
      setEvidenceList(data.evidence);
    } catch (err) {
      console.error('Reports evidence error:', err);
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchEvidence();
  }, [fetchEvidence]);

  const handleDownloadPdf = async (evidence: Evidence) => {
    if (!token) return;
    try {
      setDownloadingId(evidence.id);
      const res = await fetch(`/api/evidence/report/${evidence.id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) {
        const errorJson = await res.json();
        throw new Error(errorJson.error || 'Failed to render forensic report');
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `DEIV-Certificate-${evidence.id}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();

      setNotification({
        type: 'success',
        message: `Forensic Evidence Certificate PDF for ${evidence.id} successfully rendered and downloaded.`,
      });
    } catch (err: unknown) {
      setNotification({
        type: 'error',
        message: err instanceof Error ? err.message : 'Report generation error',
      });
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-6 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold uppercase tracking-wider text-slate-100 font-mono">
              Forensic PDF Report Center
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Generate and export official Forensic Evidence Certificates containing byte-level SHA-256 verification results, chronological custody logs, and audit chain references.
          </p>
        </div>
        <span className="text-xs font-mono text-cyan-400 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 self-start sm:self-auto">
          PDFKit Forensic Engine
        </span>
      </div>

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

      {/* Evidence Certification List */}
      <div className="p-6 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2">
            <FileCheck2 className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
              Certifiable Evidence Records ({evidenceList.length})
            </h3>
          </div>
          <button
            onClick={fetchEvidence}
            disabled={isLoading}
            className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-cyan-400 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {evidenceList.map((ev) => {
            const isTampered = ev.status === 'TAMPER_DETECTED';
            const isGenerating = downloadingId === ev.id;

            return (
              <div
                key={ev.id}
                className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition flex flex-col justify-between space-y-4"
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-cyan-400">{ev.case_id}</span>
                    <span
                      className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${
                        isTampered
                          ? 'bg-red-950 text-red-300 border-red-700'
                          : 'bg-emerald-950 text-emerald-300 border-emerald-700'
                      }`}
                    >
                      {ev.status}
                    </span>
                  </div>

                  <h4 className="text-sm font-bold text-slate-100 truncate">{ev.title}</h4>
                  <p className="text-xs text-slate-400 font-mono truncate">{ev.original_filename}</p>

                  <div className="p-2 rounded bg-slate-950 text-[10px] font-mono text-slate-400 truncate">
                    SHA-256: {ev.original_sha256}
                  </div>
                </div>

                <div className="flex items-center justify-between pt-3 border-t border-slate-800/80">
                  <button
                    onClick={() => onNavigate('evidence-detail', ev.id)}
                    className="text-xs text-slate-400 hover:text-cyan-400 font-medium flex items-center gap-1 font-mono"
                  >
                    <span>Inspect</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>

                  <button
                    onClick={() => handleDownloadPdf(ev)}
                    disabled={isGenerating}
                    className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs shadow-sm flex items-center gap-1.5 transition disabled:opacity-50"
                  >
                    <Download className={`w-3.5 h-3.5 ${isGenerating ? 'animate-bounce' : ''}`} />
                    <span>{isGenerating ? 'Compiling PDF...' : 'Download Certificate'}</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
