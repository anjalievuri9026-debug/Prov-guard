import React, { useState, useRef } from 'react';
import {
  UploadCloud,
  FileCheck2,
  AlertTriangle,
  FileText,
  ShieldCheck,
  CheckCircle2,
  ArrowRight,
  Fingerprint,
  HardDrive,
  Copy,
  Check,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { NavPage } from '../components/Sidebar';

interface UploadPageProps {
  onNavigate: (page: NavPage, evidenceId?: string) => void;
}

export const UploadPage: React.FC<UploadPageProps> = ({ onNavigate }) => {
  const { token, user } = useAuth();
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [caseId, setCaseId] = useState<string>('CASE-2026-001');
  const [title, setTitle] = useState<string>('');
  const [notes, setNotes] = useState<string>('');
  const [tags, setTags] = useState<string>('digital_forensics,acquisition');

  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successResult, setSuccessResult] = useState<{
    id: string;
    caseId: string;
    title: string;
    originalFilename: string;
    fileSizeBytes: number;
    sha256: string;
    auditSequence: number;
  } | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (file.size > 50 * 1024 * 1024) {
        setError('Selected file exceeds maximum allowed limit (50 MB).');
        setSelectedFile(null);
        return;
      }
      setSelectedFile(file);
      setError(null);
      if (!title) {
        setTitle(file.name.replace(/\.[^/.]+$/, '').replace(/[-_]/g, ' '));
      }
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) {
      setError('Please select an evidence file for forensic ingestion.');
      return;
    }
    if (!caseId.trim()) {
      setError('Case ID reference is required.');
      return;
    }
    if (!title.trim()) {
      setError('Evidence title is required.');
      return;
    }

    setIsUploading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);
      formData.append('case_id', caseId.trim().toUpperCase());
      formData.append('title', title.trim());
      formData.append('notes', notes.trim());
      formData.append('tags', tags.trim());

      const res = await fetch('/api/evidence/upload', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
        },
        body: formData,
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Evidence acquisition failed');
      }

      setSuccessResult(data.evidence);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsUploading(false);
    }
  };

  const copyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
        <div>
          <h2 className="text-base font-bold uppercase tracking-wider text-slate-100 flex items-center gap-2">
            <UploadCloud className="w-5 h-5 text-cyan-400" />
            <span>Forensic Evidence Acquisition & Ingestion</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Ingest digital artifacts into private, restricted vault storage with automated server-side SHA-256 calculation.
          </p>
        </div>
        <span className="text-xs font-mono text-cyan-400 px-2.5 py-1 rounded bg-slate-900 border border-slate-800">
          MAX 50MB
        </span>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/60 border border-red-800/80 text-red-200 text-xs flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <p className="font-bold">Ingestion Failure</p>
            <p className="text-red-300/90">{error}</p>
          </div>
        </div>
      )}

      {successResult ? (
        <div className="p-6 rounded-xl bg-[#0b0f19] border border-emerald-800/80 shadow-[0_0_25px_rgba(16,185,129,0.15)] space-y-4">
          <div className="flex items-center gap-3 text-emerald-400 pb-3 border-b border-slate-800/80">
            <CheckCircle2 className="w-7 h-7 shrink-0" />
            <div>
              <h3 className="font-bold text-sm text-slate-100">
                EVIDENCE SUCCESSFULLY ACQUIRED & SEALED
              </h3>
              <p className="text-xs text-emerald-400 font-mono">
                Cryptographic SHA-256 calculated on server byte-stream • Linked to Audit Log #{successResult.auditSequence}
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-slate-400 text-[10px] uppercase font-mono block">Assigned Evidence ID</span>
              <span className="text-slate-100 font-bold font-mono text-sm">{successResult.id}</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-slate-400 text-[10px] uppercase font-mono block">Case Reference</span>
              <span className="text-cyan-400 font-bold font-mono text-sm">{successResult.caseId}</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-slate-400 text-[10px] uppercase font-mono block">Original Filename</span>
              <span className="text-slate-200 font-mono">{successResult.originalFilename}</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-slate-400 text-[10px] uppercase font-mono block">Stored File Size</span>
              <span className="text-slate-200 font-mono">
                {successResult.fileSizeBytes.toLocaleString()} bytes ({(successResult.fileSizeBytes / 1024).toFixed(1)} KB)
              </span>
            </div>
          </div>

          {/* Cryptographic SHA-256 Box */}
          <div className="p-3 rounded-lg bg-slate-950 border border-cyan-800/60 space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase font-mono text-cyan-400 flex items-center gap-1 font-bold">
                <Fingerprint className="w-3.5 h-3.5" />
                OFFICIAL INGESTION SHA-256 DIGEST
              </span>
              <button
                onClick={() => copyHash(successResult.sha256)}
                className="text-[10px] font-mono text-slate-400 hover:text-cyan-400 flex items-center gap-1"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <div className="font-mono text-xs text-emerald-400 break-all select-all">
              {successResult.sha256}
            </div>
          </div>

          <div className="flex items-center justify-between pt-3 border-t border-slate-800/80">
            <button
              onClick={() => {
                setSuccessResult(null);
                setSelectedFile(null);
                setTitle('');
                setNotes('');
              }}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition"
            >
              Acquire Another Evidence File
            </button>

            <button
              onClick={() => onNavigate('evidence-detail', successResult.id)}
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-2 transition"
            >
              <span>Inspect Evidence Details</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="p-6 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm space-y-5">
          {/* File Dropzone */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-2 uppercase tracking-wider">
              Evidence Binary / Artifact File
            </label>
            <div
              onClick={() => fileInputRef.current?.click()}
              className="border-2 border-dashed border-slate-700 hover:border-cyan-500/80 bg-slate-900/60 hover:bg-slate-900/90 rounded-xl p-8 text-center cursor-pointer transition group"
            >
              <input
                ref={fileInputRef}
                type="file"
                onChange={handleFileChange}
                className="hidden"
              />
              <div className="flex flex-col items-center">
                <div className="w-12 h-12 rounded-xl bg-slate-800 group-hover:bg-cyan-950/80 border border-slate-700 group-hover:border-cyan-600/50 flex items-center justify-center text-slate-400 group-hover:text-cyan-400 transition mb-3">
                  <HardDrive className="w-6 h-6" />
                </div>
                {selectedFile ? (
                  <div>
                    <p className="text-sm font-bold text-slate-100 font-mono">{selectedFile.name}</p>
                    <p className="text-xs text-cyan-400 font-mono mt-1">
                      {(selectedFile.size / 1024).toFixed(1)} KB • {selectedFile.type || 'binary/raw'}
                    </p>
                    <p className="text-[11px] text-slate-500 mt-2">Click to replace file</p>
                  </div>
                ) : (
                  <div>
                    <p className="text-xs font-semibold text-slate-200">
                      Click to browse or drag evidence file here
                    </p>
                    <p className="text-[11px] text-slate-500 mt-1">
                      Memory dumps (.raw), PCAP captures (.pcap), disk images, logs, documents up to 50MB
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                Case Identifier Reference
              </label>
              <input
                type="text"
                value={caseId}
                onChange={(e) => setCaseId(e.target.value)}
                placeholder="e.g. CASE-2026-ALPHA"
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                required
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
                Evidence Title
              </label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="e.g. Router Syslog Extract"
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
              Forensic Acquisition Notes & Custody Justification
            </label>
            <textarea
              rows={3}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Record forensic environment, physical write-blocker details, acquisition location, and authorized officer notes..."
              className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5 uppercase tracking-wider">
              Forensic Tags (comma-separated)
            </label>
            <input
              type="text"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="e.g. network, malware, packet_capture, disk_image"
              className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="pt-2 flex items-center justify-between">
            <div className="text-[11px] text-slate-500 flex items-center gap-1 font-mono">
              <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span>Acquiring as: {user?.fullName} ({user?.role})</span>
            </div>

            <button
              type="submit"
              disabled={isUploading || !selectedFile}
              className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-xs shadow-[0_0_20px_rgba(6,182,212,0.25)] transition flex items-center gap-2 disabled:opacity-50"
            >
              {isUploading ? (
                <span>Streaming & Hashing Bytes...</span>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  <span>Seal & Store Evidence</span>
                </>
              )}
            </button>
          </div>
        </form>
      )}
    </div>
  );
};
