import React, { useState, useEffect, useCallback } from 'react';
import {
  History,
  Filter,
  RefreshCw,
  Search,
  ExternalLink,
  ShieldCheck,
  AlertTriangle,
  FileCheck2,
  Lock,
} from 'lucide-react';
import { CustodyEvent } from '../types';
import { useAuth } from '../context/AuthContext';
import { NavPage } from '../components/Sidebar';

interface CustodyPageProps {
  onNavigate: (page: NavPage, evidenceId?: string) => void;
}

export const CustodyPage: React.FC<CustodyPageProps> = ({ onNavigate }) => {
  const { token } = useAuth();
  const [events, setEvents] = useState<CustodyEvent[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [actionFilter, setActionFilter] = useState<string>('');
  const [evidenceFilter, setEvidenceFilter] = useState<string>('');

  const fetchCustody = useCallback(async () => {
    if (!token) return;
    try {
      setIsLoading(true);
      const res = await fetch('/api/stats/dashboard', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error('Failed to load custody data');
      const data = await res.json();
      setEvents(data.recentCustody || []);
    } catch (err) {
      console.error('Custody load error:', err);
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchCustody();
  }, [fetchCustody]);

  const filteredEvents = events.filter((e) => {
    if (actionFilter && e.action !== actionFilter) return false;
    if (evidenceFilter && !e.evidence_id.toLowerCase().includes(evidenceFilter.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="p-4 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm flex flex-col sm:flex-row gap-3 items-stretch sm:items-center justify-between">
        <div className="flex-1 relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={evidenceFilter}
            onChange={(e) => setEvidenceFilter(e.target.value)}
            placeholder="Filter by Evidence Identifier (e.g. EVD-2026)..."
            className="w-full pl-9 pr-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-2">
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="">All Forensic Actions</option>
            <option value="INGESTION">INGESTION</option>
            <option value="VERIFICATION_PASSED">VERIFICATION_PASSED</option>
            <option value="VERIFICATION_FAILED">VERIFICATION_FAILED</option>
            <option value="DOWNLOAD_SUCCESS">DOWNLOAD_SUCCESS</option>
            <option value="DOWNLOAD_BLOCKED">DOWNLOAD_BLOCKED</option>
            <option value="CUSTODY_TRANSFER">CUSTODY_TRANSFER</option>
            <option value="REPORT_GENERATED">REPORT_GENERATED</option>
          </select>

          <button
            onClick={fetchCustody}
            disabled={isLoading}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-cyan-400 transition"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Custody Event Feed */}
      <div className="p-6 rounded-xl bg-[#0b0f19] border border-slate-800/90 shadow-sm space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2">
            <History className="w-5 h-5 text-cyan-400" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200">
              Master Chain of Custody Audit ({filteredEvents.length} events logged)
            </h2>
          </div>
          <span className="text-xs font-mono text-cyan-400">CHRONOLOGICAL WITNESS TRAIL</span>
        </div>

        {filteredEvents.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-xs">
            No custody events found matching current filter.
          </div>
        ) : (
          <div className="relative pl-6 space-y-4 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
            {filteredEvents.map((event) => {
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
                    className={`absolute -left-[27px] top-2 w-3.5 h-3.5 rounded-full border-2 ${
                      isFailure
                        ? 'bg-red-500 border-red-950 ring-4 ring-red-950'
                        : 'bg-cyan-500 border-cyan-950 ring-4 ring-cyan-950'
                    }`}
                  />

                  <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/90 group-hover:border-slate-700 transition space-y-2">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${
                            isFailure
                              ? 'bg-red-950 text-red-300 border-red-800'
                              : 'bg-cyan-950 text-cyan-300 border-cyan-800'
                          }`}
                        >
                          {event.action}
                        </span>

                        <button
                          onClick={() => onNavigate('evidence-detail', event.evidence_id)}
                          className="font-mono text-xs font-bold text-slate-200 hover:text-cyan-400 flex items-center gap-1"
                        >
                          <span>{event.evidence_id}</span>
                          <ExternalLink className="w-3 h-3 text-slate-500" />
                        </button>

                        <span className="text-xs text-slate-400">
                          by <strong className="text-slate-200">{event.actor_name}</strong> ({event.actor_role})
                        </span>
                      </div>

                      <span className="text-[11px] font-mono text-slate-500">{event.timestamp_utc}</span>
                    </div>

                    <div className="p-2.5 rounded bg-slate-950/80 border border-slate-800/80 text-xs font-mono text-slate-300 space-y-0.5">
                      {Object.entries(parsedDetails).map(([key, val]) => (
                        <div key={key} className="flex items-start gap-2">
                          <span className="text-slate-500 min-w-[130px]">{key}:</span>
                          <span className="text-slate-300 break-all">{String(val)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
