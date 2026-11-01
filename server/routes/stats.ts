import { Router, Response } from 'express';
import { db, verifyAuditChain, CustodyEventRow, EvidenceRow } from '../db.js';
import { AuthenticatedRequest, requireAuth } from '../middleware/auth.js';

export const statsRouter = Router();

statsRouter.get('/dashboard', requireAuth, (_req: AuthenticatedRequest, res: Response): void => {
  // Counts
  const totalEvidence = (db.prepare('SELECT COUNT(*) as count FROM evidence').get() as { count: number }).count;
  const verifiedCount = (db.prepare("SELECT COUNT(*) as count FROM evidence WHERE status = 'VERIFIED'").get() as { count: number }).count;
  const tamperedCount = (db.prepare("SELECT COUNT(*) as count FROM evidence WHERE status = 'TAMPER_DETECTED'").get() as { count: number }).count;
  const unverifiedCount = (db.prepare("SELECT COUNT(*) as count FROM evidence WHERE status = 'UNVERIFIED'").get() as { count: number }).count;
  const missingCount = (db.prepare("SELECT COUNT(*) as count FROM evidence WHERE status = 'MISSING_FILE'").get() as { count: number }).count;

  const totalCustodyEvents = (db.prepare('SELECT COUNT(*) as count FROM custody_events').get() as { count: number }).count;
  const totalAuditLogs = (db.prepare('SELECT COUNT(*) as count FROM audit_log').get() as { count: number }).count;

  // Recent evidence
  const recentEvidence = db.prepare(`
    SELECT id, case_id, title, original_filename, file_size_bytes, original_sha256, status, created_at, uploader_name, is_tampered_demo
    FROM evidence
    ORDER BY created_at DESC
    LIMIT 6
  `).all() as unknown as EvidenceRow[];

  // Recent custody actions
  const recentCustody = db.prepare(`
    SELECT c.*, e.case_id, e.title as evidence_title
    FROM custody_events c
    LEFT JOIN evidence e ON c.evidence_id = e.id
    ORDER BY c.timestamp_utc DESC
    LIMIT 8
  `).all() as unknown as (CustodyEventRow & { case_id: string; evidence_title: string })[];

  // Case summaries
  const caseSummaries = db.prepare(`
    SELECT case_id, COUNT(*) as count, MAX(created_at) as last_updated
    FROM evidence
    GROUP BY case_id
    ORDER BY last_updated DESC
    LIMIT 10
  `).all();

  // Audit chain health
  const chainVerification = verifyAuditChain();

  res.json({
    metrics: {
      totalEvidence,
      verifiedCount,
      tamperedCount,
      unverifiedCount,
      missingCount,
      totalCustodyEvents,
      totalAuditLogs,
    },
    chainHealth: {
      isValid: chainVerification.isValid,
      totalEntries: chainVerification.totalEntries,
      tipHash: chainVerification.tipHash,
      reason: chainVerification.reason,
    },
    recentEvidence,
    recentCustody,
    caseSummaries,
  });
});
