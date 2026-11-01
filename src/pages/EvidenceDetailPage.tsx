import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  ArrowLeft,
  CheckCircle2,
  XCircle,
  Download,
  FileText,
  History,
  AlertTriangle,
  RefreshCw,
  Copy,
  Check,
  Flame,
  Undo2,
  UserCheck,
  Send,
  Lock,
} from 'lucide-react';
import { Evidence, CustodyEvent } from '../types';
import { useAuth } from '../context/AuthContext';
import { NavPage } from '../components/Sidebar';

interface EvidenceDetailPageProps {
  evidenceId: string;
  onNavigate: (page: NavPage, evidenceId?: string) => void;
}

export const EvidenceDetailPage: React.FC<EvidenceDetailPageProps> = ({ evidenceId, onNavigate }) => {
  const { token, user, hasRole } = useAuth();
  const [evidence, setEvidence] = useState<Evidence | null>(null);
  const [custodyEvents, setCustodyEvents] = useState<CustodyEvent[]>([]);
  const [auditEntries, setAuditEntries] = useState<{ sequence_num: number; current_entry_hash: string; timestamp_utc: string; action: string }[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [isTampering, setIsTampering] = useState<boolean>(false);
  const [isDownloading, setIsDownloading] = useState<boolean>(false);
  const [isExportingPdf, setIsExportingPdf] = useState<boolean>(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Transfer Custody Modal State
  const [showTransferModal, setShowTransferModal] = useState<boolean>(false);
  const [transferRecipient, setTransferRecipient] = useState<string>('');
  const [transferRole, setTransferRole] = useState<string>('State Forensic Laboratory');
  const [transferReason, setTransferReason] = useState<string>('');
  const [isSubmittingTransfer, setIsSubmittingTransfer] = useState<boolean>(false);

  const fetchDetails = useCallback(async () => {
    if (!token || !evidenceId) return;
    try {
      setIsLoading(true);
      setError(null);
      const res = await fetch(`/api/evidence/${evidenceId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error('Evidence record not found');
      const data = await res.json();
      setEvidence(data.evidence);
      setCustodyEvents(data.custodyEvents);
      setAuditEntries(data.auditEntries);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsLoading(false);
    }
  }, [token, evidenceId]);

  useEffect(() => {
    fetchDetails();
  }, [fetchDetails]);

  const handleVerify = async () => {
    if (!token || !evidence) return;
    try {
      setIsVerifying(true);
      const res = await fetch(`/api/evidence/verify/${evidence.id}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Verification failed');

      if (data.matched) {
        setNotification({
          type: 'success',
          message: 'VERIFICATION SUCCESSFUL: Live disk bytes match recorded SHA-256 digest with 0 bit discrepancies.',
        });
      } else {
        setNotification({
          type: 'error',
          message: 'CRITICAL SECURITY FAILURE: Stored file bytes DO NOT match original ingestion digest! File has been modified.',
        });
      }

      fetchDetails();
    } catch (err: unknown) {
      setNotification({
        type: 'error',
        message: err instanceof Error ? err.message : 'Integrity verification failed',
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleTamperToggle = async () => {
    if (!token || !evidence) return;
    try {
      setIsTampering(true);
      const currentlyTampered = evidence.is_tampered_demo === 1;
      const action = currentlyTampered ? 'restore' : 'tamper';
      const res = await fetch(`/api/evidence/tamper-demo/${evidence.id}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ action }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Simulation failed');

      setNotification({
        type: currentlyTampered ? 'success' : 'error',
        message: data.message,
      });

      fetchDetails();
    } catch (err: unknown) {
      setNotification({
        type: 'error',
        message: err instanceof Error ? err.message : 'Tamper simulation failed',
      });
    } finally {
      setIsTampering(false);
    }
  };

  const handleDownload = async () => {
    if (!token || !evidence) return;
    try {
      setIsDownloading(true);
      const res = await fetch(`/api/evidence/download/${evidence.id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) {
        const errorJson = await res.json();
        setNotification({
          type: 'error',
          message: errorJson.error || 'Download blocked: evidence failed cryptographic integrity check!',
        });
        fetchDetails();
        return;
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = evidence.original_filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
    } catch (err: unknown) {
      setNotification({
        type: 'error',
        message: 'Download error: ' + (err instanceof Error ? err.message : String(err)),
      });
    } finally {
      setIsDownloading(false);
    }
  };

  const handleExportPdf = async () => {
    if (!token || !evidence) return;
    try {
      setIsExportingPdf(true);
      const res = await fetch(`/api/evidence/report/${evidence.id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) {
        const errorJson = await res.json();
        throw new Error(errorJson.error || 'Failed to generate PDF report');
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Forensic-Certificate-${evidence.id}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();

      setNotification({
        type: 'success',
        message: 'Forensic PDF Evidence Certificate generated and downloaded successfully.',
      });
      fetchDetails();
    } catch (err: unknown) {
      setNotification({
        type: 'error',
        message: err instanceof Error ? err.message : 'PDF generation failed',
      });
    } finally {
      setIsExportingPdf(false);
    }
  };

  const handleTransferSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!transferRecipient.trim() || !transferReason.trim()) {
      alert('Recipient name and transfer justification are required.');
      return;
    }

    try {
      setIsSubmittingTransfer(true);
      const res = await fetch(`/api/evidence/transfer/${evidenceId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          recipient_name: transferRecipient.trim(),
          recipient_role: transferRole.trim(),
          reason: transferReason.trim(),
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Transfer logging failed');

      setShowTransferModal(false);
      setTransferRecipient('');
      setTransferReason('');
      setNotification({
        type: 'success',
        message: 'Chain of custody transfer successfully logged into the permanent forensic record.',
      });
      fetchDetails();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to record transfer');
    } finally {
      setIsSubmittingTransfer(false);
    }
  };

  const copyToClipboard = (text: string, fieldId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldId);
    setTimeout(() => setCopiedField(null), 2000);
  };

  if (isLoading && !evidence) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-slate-400">
        <RefreshCw className="w-8 h-8 animate-spin text-cyan-400 mb-3" />
        <p className="text-sm font-mono">LOADING EVIDENCE DOSSIER...</p>
      </div>
    );
  }

  if (error || !evidence) {
    return (
      <div className="p-6 rounded-xl bg-red-950/40 border border-red-800 text-red-200 space-y-3">
        <p className="font-bold">Evidence Not Found</p>
        <p className="text-xs text-red-300">{error || 'Unable to locate evidence record'}</p>
        <button
          onClick={() => onNavigate('vault')}
          className="px-3 py-1.5 rounded bg-slate-800 text-slate-200 text-xs font-semibold"
        >
          Return to Vault
        </button>
      </div>
    );
  }

  const isTampered = evidence.status === 'TAMPER_DETECTED';

  return (
    <div className="space-y-6">
      {/* Back Button & Actions Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
        <button
          onClick={() => onNavigate('vault')}
          className="inline-flex items-center gap-2 text-xs text-slate-400 hover:text-cyan-400 transition font-mono"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>BACK TO EVIDENCE VAULT</span>
        </button>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Live Verification Trigger */}
          <button
            onClick={handleVerify}
            disabled={isVerifying}
            className="px-3 py-1.5 rounded-lg bg-cyan-950/90 hover:bg-cyan-900 border border-cyan-600/60 text-cyan-200 text-xs font-semibold flex items-center gap-1.5 transition"
          >
            <ShieldCheck className={`w-3.5 h-3.5 ${isVerifying ? 'animate-spin' : 'text-cyan-400'}`} />
            <span>{isVerifying ? 'Calculating SHA-256...' : 'Verify Disk Bytes'}</span>
          </button>

          {/* Transfer Custody Button (Investigator/Admin) */}
          {hasRole('Administrator', 'Investigator') && (
            <button
              onClick={() => setShowTransferModal(true)}
              className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-1.5 transition"
            >
              <UserCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span>Log Custody Transfer</span>
            </button>
          )}

          {/* PDF Certificate Export */}
          <button
            onClick={handleExportPdf}
            disabled={isExportingPdf}
            className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-1.5 transition"
          >
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            <span>{isExportingPdf ? 'Rendering PDF...' : 'Export PDF Report'}</span>
          </button>

          {/* Secure Download */}
          <button
            onClick={handleDownload}
            disabled={isDownloading}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition border ${
              isTampered
                ? 'bg-red-950/80 text-red-300 border-red-700 cursor-not-allowed'
                : 'bg-emerald-950/90 hover:bg-emerald-900 text-emerald-200 border-emerald-600/70'
            }`}
            title={isTampered ? 'Download blocked: Integrity failure' : 'Download authenticated file'}
          >
            <Download className="w-3.5 h-3.5" />
            <span>{isTampered ? 'Download Blocked' : 'Download File'}</span>
          </button>
        </div>
      </div>

      {/* Notification Banner */}
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

      {/* Top Dossier Grid: Metadata & Cryptographic Hash Compare */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Ingestion Specifications */}
        <div className="lg:col-span-2 space-y-4">
          <div className="p-6 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm space-y-4">
            <div className="flex items-start justify-between pb-3 border-b border-slate-800/80">
              <div>
                <span className="text-xs font-mono text-cyan-400 uppercase font-semibold">
                  {evidence.case_id}
                </span>
                <h2 className="text-lg font-bold text-slate-100 mt-0.5">{evidence.title}</h2>
              </div>
              <span
                className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-mono font-bold uppercase border ${
                  isTampered
                    ? 'bg-red-950 text-red-400 border-red-700 shadow-[0_0_15px_rgba(239,68,68,0.25)] animate-pulse'
                    : evidence.status === 'VERIFIED'
                    ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
                    : 'bg-slate-800 text-slate-300 border-slate-700'
                }`}
              >
                {isTampered ? <XCircle className="w-4 h-4 text-red-400" /> : <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                {evidence.status}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-mono uppercase block">Evidence ID</span>
                <span className="font-mono text-slate-100 font-bold text-sm">{evidence.id}</span>
              </div>

              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-mono uppercase block">Original Filename</span>
                <span className="font-mono text-slate-200">{evidence.original_filename}</span>
              </div>

              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-mono uppercase block">File Size (Bytes)</span>
                <span className="font-mono text-slate-200">
                  {evidence.file_size_bytes.toLocaleString()} bytes ({(evidence.file_size_bytes / 1024).toFixed(1)} KB)
                </span>
              </div>

              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-mono uppercase block">MIME Classification</span>
                <span className="font-mono text-cyan-400">{evidence.mime_type}</span>
              </div>

              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-mono uppercase block">Acquiring Officer</span>
                <span className="text-slate-200 font-semibold">{evidence.uploader_name}</span>
                <span className="text-[11px] text-slate-400 block font-mono">{evidence.uploader_role}</span>
              </div>

              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-mono uppercase block">Ingestion UTC Timestamp</span>
                <span className="font-mono text-slate-200">{evidence.created_at}</span>
              </div>
            </div>

            {/* Notes & Tags */}
            {evidence.notes && (
              <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800/80 text-xs">
                <span className="text-[10px] text-slate-400 uppercase font-mono block font-semibold mb-1">
                  Forensic Custody Acquisition Notes
                </span>
                <p className="text-slate-300 leading-relaxed">{evidence.notes}</p>
              </div>
            )}

            {evidence.tags && (
              <div className="flex items-center gap-1.5 flex-wrap pt-1">
                {evidence.tags.split(',').map((tag) => (
                  <span
                    key={tag}
                    className="px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800 text-[10px] font-mono"
                  >
                    #{tag.trim()}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Dual Cryptographic SHA-256 Inspection Console */}
          <div className="p-6 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
                  Cryptographic SHA-256 Digest Comparison
                </h3>
              </div>
              <span className="text-[11px] font-mono text-slate-400">SERVER-STREAMED VERIFICATION</span>
            </div>

            {/* Recorded Ingestion Digest */}
            <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono uppercase text-slate-400 font-bold">
                  [1] Recorded Ingestion SHA-256 (Canonical Forensic Baseline)
                </span>
                <button
                  onClick={() => copyToClipboard(evidence.original_sha256, 'original')}
                  className="text-[10px] text-slate-500 hover:text-cyan-400 flex items-center gap-1 font-mono"
                >
                  {copiedField === 'original' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedField === 'original' ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <div className="font-mono text-xs text-emerald-400 break-all select-all">
                {evidence.original_sha256}
              </div>
            </div>

            {/* Live Stored Disk Byte Digest */}
            <div
              className={`p-3.5 rounded-lg border space-y-1 ${
                isTampered
                  ? 'bg-red-950/40 border-red-800/80'
                  : 'bg-slate-950/80 border-slate-800'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono uppercase text-slate-400 font-bold flex items-center gap-1.5">
                  <span>[2] Live Disk Bytes Recalculated SHA-256</span>
                  {evidence.last_verified_at && (
                    <span className="text-slate-500 font-normal">
                      (Checked: {new Date(evidence.last_verified_at).toLocaleTimeString()})
                    </span>
                  )}
                </span>
                {evidence.last_calculated_sha256 && (
                  <button
                    onClick={() => copyToClipboard(evidence.last_calculated_sha256!, 'live')}
                    className="text-[10px] text-slate-500 hover:text-cyan-400 flex items-center gap-1 font-mono"
                  >
                    {copiedField === 'live' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedField === 'live' ? 'Copied' : 'Copy'}</span>
                  </button>
                )}
              </div>
              <div
                className={`font-mono text-xs break-all select-all ${
                  isTampered ? 'text-red-400 font-bold' : 'text-cyan-400'
                }`}
              >
                {evidence.last_calculated_sha256 || 'Click "Verify Disk Bytes" above to calculate'}
              </div>
            </div>

            {/* Comparison Verdict */}
            <div
              className={`p-3 rounded-lg border text-xs flex items-center gap-3 ${
                isTampered
                  ? 'bg-red-950/80 border-red-700 text-red-200'
                  : 'bg-emerald-950/60 border-emerald-800/60 text-emerald-200'
              }`}
            >
              {isTampered ? (
                <XCircle className="w-5 h-5 text-red-400 shrink-0" />
              ) : (
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
              )}
              <div>
                <p className="font-bold">
                  {isTampered ? 'INTEGRITY MISMATCH DETECTED' : 'CRYPTOGRAPHIC MATCH CONFIRMED'}
                </p>
                <p className="text-[11px] opacity-90 mt-0.5">
                  {isTampered
                    ? 'The stored file bytes on disk have been altered! Any downstream evidence report or download is locked.'
                    : 'The live file bytes stored in private vault storage match the original baseline digest with 100% bit accuracy.'}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Right 1 Col: Educational Simulation & Linked Audit Nodes */}
        <div className="space-y-4">
          {/* Educational Tamper Testing Tool */}
          {hasRole('Administrator', 'Investigator') && (
            <div className="p-5 rounded-xl bg-[#0b0f19] border border-amber-900/50 shadow-sm space-y-3">
              <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
                <Flame className="w-4 h-4 text-amber-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-amber-300 font-mono">
                  Educational Tamper Simulator
                </h3>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Test DEIV&apos;s forensic detection engine by flipping a single byte in the actual file stored on the server disk.
              </p>

              <button
                onClick={handleTamperToggle}
                disabled={isTampering}
                className={`w-full py-2 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition border ${
                  evidence.is_tampered_demo === 1
                    ? 'bg-amber-950 text-amber-200 border-amber-600 hover:bg-amber-900'
                    : 'bg-red-950/60 hover:bg-red-900 text-red-300 border-red-800/80'
                }`}
              >
                {evidence.is_tampered_demo === 1 ? (
                  <>
                    <Undo2 className="w-4 h-4" />
                    <span>Restore Pristine File</span>
                  </>
                ) : (
                  <>
                    <Flame className="w-4 h-4" />
                    <span>Inject 1-Bit File Tampering</span>
                  </>
                )}
              </button>

              <p className="text-[10px] text-slate-500 font-mono">
                {evidence.is_tampered_demo === 1
                  ? 'File is currently altered on disk. Click "Verify Disk Bytes" to observe the integrity failure.'
                  : 'Safe: Automatically backed up for 1-click recovery.'}
              </p>
            </div>
          )}

          {/* Linked Audit Trail Nodes */}
          <div className="p-5 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-200 font-mono">
                Linked Audit Nodes
              </span>
              <button
                onClick={() => onNavigate('audit')}
                className="text-[11px] text-cyan-400 hover:underline"
              >
                Audit Chain
              </button>
            </div>

            <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
              {auditEntries.map((entry) => (
                <div key={entry.sequence_num} className="p-2.5 rounded bg-slate-950/80 border border-slate-800 text-[11px]">
                  <div className="flex items-center justify-between text-slate-400 font-mono text-[10px]">
                    <span className="text-cyan-400 font-bold">Node #{entry.sequence_num}</span>
                    <span>{new Date(entry.timestamp_utc).toLocaleTimeString()}</span>
                  </div>
                  <div className="font-semibold text-slate-200 mt-1">{entry.action}</div>
                  <div className="text-[9px] font-mono text-slate-500 truncate mt-0.5">
                    Hash: {entry.current_entry_hash}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Full Chronological Chain of Custody Timeline */}
      <div className="p-6 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2">
            <History className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
              Complete Chain of Custody Timeline ({custodyEvents.length} events)
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-500">TAMPER-EVIDENT ORDER</span>
        </div>

        <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
          {custodyEvents.map((event) => {
            const isFailure = event.action.includes('FAIL') || event.action.includes('BLOCKED');
            let parsedDetails: Record<string, unknown> = {};
            try {
              parsedDetails = JSON.parse(event.details_json);
            } catch {
              parsedDetails = { detail: event.details_json };
            }

            return (
              <div key={event.id} className="relative group">
                <div
                  className={`absolute -left-[27px] top-1.5 w-3.5 h-3.5 rounded-full border-2 ${
                    isFailure
                      ? 'bg-red-500 border-red-950 ring-4 ring-red-950'
                      : 'bg-cyan-500 border-cyan-950 ring-4 ring-cyan-950'
                  }`}
                />

                <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 group-hover:border-slate-700 transition space-y-2">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${
                          isFailure
                            ? 'bg-red-950 text-red-300 border-red-800'
                            : 'bg-cyan-950 text-cyan-300 border-cyan-800'
                        }`}
                      >
                        {event.action}
                      </span>
                      <span className="text-xs font-bold text-slate-200">{event.actor_name}</span>
                      <span className="text-[11px] text-slate-400 font-mono">({event.actor_role})</span>
                    </div>

                    <span className="text-[11px] font-mono text-slate-400">
                      {event.timestamp_utc}
                    </span>
                  </div>

                  <div className="p-2.5 rounded bg-slate-950/80 border border-slate-800/80 text-xs font-mono text-slate-300 space-y-1">
                    {Object.entries(parsedDetails).map(([key, val]) => (
                      <div key={key} className="flex items-start gap-2">
                        <span className="text-slate-500 min-w-[120px]">{key}:</span>
                        <span className="text-slate-300 break-all">{String(val)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Custody Transfer Modal */}
      {showTransferModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0b0f19] border border-slate-800 rounded-xl p-6 w-full max-w-lg shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <UserCheck className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold uppercase tracking-wider text-slate-100">
                  Record Official Custody Transfer
                </h3>
              </div>
              <button
                onClick={() => setShowTransferModal(false)}
                className="text-slate-400 hover:text-slate-200 text-sm font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleTransferSubmit} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1 uppercase tracking-wider">
                  Transfer Recipient Name / Officer
                </label>
                <input
                  type="text"
                  value={transferRecipient}
                  onChange={(e) => setTransferRecipient(e.target.value)}
                  placeholder="e.g. Special Agent Robert Miller"
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1 uppercase tracking-wider">
                  Recipient Agency or Forensic Laboratory
                </label>
                <input
                  type="text"
                  value={transferRole}
                  onChange={(e) => setTransferRole(e.target.value)}
                  placeholder="e.g. State Forensic Crime Lab / Evidence Vault A"
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1 uppercase tracking-wider">
                  Custody Transfer Justification & Notes
                </label>
                <textarea
                  rows={3}
                  value={transferReason}
                  onChange={(e) => setTransferReason(e.target.value)}
                  placeholder="e.g. Transferred for secondary hardware write-block forensic image extraction under subpoena..."
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-100 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowTransferModal(false)}
                  className="px-3 py-2 rounded-lg bg-slate-800 text-slate-300 font-semibold hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmittingTransfer}
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold flex items-center gap-2"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>{isSubmittingTransfer ? 'Recording...' : 'Commit Transfer to Log'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
