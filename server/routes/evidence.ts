import { Router, Response } from 'express';
import multer from 'multer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { db, EvidenceRow, CustodyEventRow, appendAuditLog } from '../db.js';
import { AuthenticatedRequest, requireAuth, requireRole } from '../middleware/auth.js';
import {
  generateStorageFilename,
  saveEvidenceFile,
  verifyEvidenceIntegrity,
  resolveSafePath,
  injectTampering,
  restorePristineFile,
  removeEvidenceFile,
} from '../storage.js';
import { generateEvidencePdfReport } from '../reports.js';

export const evidenceRouter = Router();

// Configure memory storage for initial upload validation and streaming to private storage
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB maximum evidence size
  },
});

// List all evidence
evidenceRouter.get('/', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  const { case_id, status, search } = req.query;

  let query = 'SELECT * FROM evidence WHERE 1=1';
  const params: (string | number)[] = [];

  if (case_id && typeof case_id === 'string' && case_id.trim() !== '') {
    query += ' AND case_id = ?';
    params.push(case_id.trim().toUpperCase());
  }

  if (status && typeof status === 'string' && status.trim() !== '') {
    query += ' AND status = ?';
    params.push(status.trim().toUpperCase());
  }

  if (search && typeof search === 'string' && search.trim() !== '') {
    query += ' AND (id LIKE ? OR title LIKE ? OR original_filename LIKE ? OR original_sha256 LIKE ?)';
    const wildcard = `%${search.trim()}%`;
    params.push(wildcard, wildcard, wildcard, wildcard);
  }

  query += ' ORDER BY created_at DESC';

  const stmt = db.prepare(query);
  const rows = stmt.all(...params);
  res.json({ evidence: rows });
});

// Single evidence details + custody history
evidenceRouter.get('/:id', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  const { id } = req.params;

  const stmt = db.prepare('SELECT * FROM evidence WHERE id = ?');
  const evidence = stmt.get(id) as EvidenceRow | undefined;

  if (!evidence) {
    res.status(404).json({ error: 'Evidence record not found.' });
    return;
  }

  const custodyStmt = db.prepare('SELECT * FROM custody_events WHERE evidence_id = ? ORDER BY timestamp_utc DESC');
  const custodyEvents = custodyStmt.all(id) as unknown as CustodyEventRow[];

  const auditStmt = db.prepare('SELECT sequence_num, current_entry_hash, timestamp_utc, action FROM audit_log WHERE evidence_id = ? ORDER BY sequence_num DESC');
  const auditEntries = auditStmt.all(id);

  res.json({
    evidence,
    custodyEvents,
    auditEntries,
  });
});

// Evidence Ingestion / Upload (Investigator or Admin)
evidenceRouter.post(
  '/upload',
  requireAuth,
  requireRole('Administrator', 'Investigator'),
  (req, res, next) => {
    upload.single('file')(req, res, (err) => {
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          res.status(413).json({ error: 'File rejected: evidence size exceeds the 50MB maximum allowable limit.' });
          return;
        }
        res.status(400).json({ error: `Upload error: ${err.message}` });
        return;
      } else if (err) {
        res.status(400).json({ error: `Upload rejected: ${err.message}` });
        return;
      }
      next();
    });
  },
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      if (!req.file) {
        res.status(400).json({ error: 'A valid evidence file is required.' });
        return;
      }

      const { case_id, title, notes, tags } = req.body;

      if (!case_id || typeof case_id !== 'string' || case_id.trim() === '') {
        res.status(400).json({ error: 'Case ID reference is required (e.g., CASE-2026-001).' });
        return;
      }

      const cleanCaseId = case_id.trim().toUpperCase();
      if (!/^[A-Z0-9_.-]{3,50}$/.test(cleanCaseId)) {
        res.status(400).json({ error: 'Case ID must be between 3 and 50 alphanumeric characters (hyphens and underscores allowed).' });
        return;
      }

      if (!title || typeof title !== 'string' || title.trim() === '') {
        res.status(400).json({ error: 'Evidence title is required.' });
        return;
      }

      const originalFilename = path.basename(req.file.originalname || 'evidence.bin');
      const storageFilename = generateStorageFilename(originalFilename);
      const mimeType = req.file.mimetype || 'application/octet-stream';

      // Write file to private disk and calculate real byte-level SHA-256
      const { fileSizeBytes, calculatedSha256 } = await saveEvidenceFile(req.file.buffer, storageFilename);

      const evidenceId = `EVD-${Date.now().toString().slice(-6)}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
      const now = new Date().toISOString();

      try {
        db.exec('BEGIN TRANSACTION');

        // Insert evidence record
        const insertEvidence = db.prepare(`
          INSERT INTO evidence (
            id, case_id, title, original_filename, storage_filename, mime_type,
            file_size_bytes, original_sha256, uploader_id, uploader_name, uploader_role,
            created_at, status, last_verified_at, last_calculated_sha256, notes, tags
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'VERIFIED', ?, ?, ?, ?)
        `);

        insertEvidence.run(
          evidenceId,
          cleanCaseId,
          title.trim(),
          originalFilename,
          storageFilename,
          mimeType,
          fileSizeBytes,
          calculatedSha256,
          req.user!.id,
          req.user!.full_name,
          req.user!.role,
          now,
          now,
          calculatedSha256,
          notes || '',
          tags || ''
        );

        // Record Chain of Custody Ingestion Event
        const custodyEventId = `CST-${crypto.randomUUID()}`;
        const insertCustody = db.prepare(`
          INSERT INTO custody_events (
            id, evidence_id, action, actor_id, actor_name, actor_role, timestamp_utc, details_json, created_at
          ) VALUES (?, ?, 'INGESTION', ?, ?, ?, ?, ?, ?)
        `);

        const custodyDetails = {
          action: 'Initial forensic acquisition and storage',
          original_filename: originalFilename,
          file_size_bytes: fileSizeBytes,
          computed_sha256: calculatedSha256,
          mime_type: mimeType,
        };

        insertCustody.run(
          custodyEventId,
          evidenceId,
          req.user!.id,
          req.user!.full_name,
          req.user!.role,
          now,
          JSON.stringify(custodyDetails),
          now
        );

        // Append to Tamper-Evident Audit Log
        const auditLog = appendAuditLog({
          actorId: req.user!.id,
          actorName: req.user!.full_name,
          actorRole: req.user!.role,
          action: 'EVIDENCE_INGESTED',
          evidenceId,
          details: {
            case_id: cleanCaseId,
            title: title.trim(),
            original_filename: originalFilename,
            sha256: calculatedSha256,
            file_size: fileSizeBytes,
          },
        });

        db.exec('COMMIT');

        res.status(201).json({
          message: 'Evidence successfully ingested into private vault with verified SHA-256 hash.',
          evidence: {
            id: evidenceId,
            caseId: cleanCaseId,
            title: title.trim(),
            originalFilename,
            fileSizeBytes,
            sha256: calculatedSha256,
            createdAt: now,
            status: 'VERIFIED',
            auditSequence: auditLog.sequence_num,
          },
        });
      } catch (dbErr) {
        db.exec('ROLLBACK');
        // Clean up file from private storage on transaction abort
        await removeEvidenceFile(storageFilename);
        throw dbErr;
      }
    } catch (err: unknown) {
      console.error('Evidence upload error:', err);
      res.status(500).json({ error: 'Failed to ingest evidence: ' + (err instanceof Error ? err.message : String(err)) });
    }
  }
);

// Cryptographic Integrity Verification Endpoint (recalls actual disk bytes)
evidenceRouter.post('/verify/:id', requireAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const { id } = req.params;

    const stmt = db.prepare('SELECT * FROM evidence WHERE id = ?');
    const evidence = stmt.get(id) as EvidenceRow | undefined;

    if (!evidence) {
      res.status(404).json({ error: 'Evidence record not found.' });
      return;
    }

    const now = new Date().toISOString();

    // Verify live disk file bytes
    const verification = await verifyEvidenceIntegrity(evidence.storage_filename, evidence.original_sha256);

    const newStatus = verification.status;

    // Update database status and verification timestamp
    const updateStmt = db.prepare(`
      UPDATE evidence
      SET status = ?, last_verified_at = ?, last_calculated_sha256 = ?
      WHERE id = ?
    `);
    updateStmt.run(newStatus, now, verification.calculatedSha256, id);

    // Record Custody Event
    const custodyEventId = `CST-${crypto.randomUUID()}`;
    const custodyAction = verification.matched ? 'VERIFICATION_PASSED' : 'VERIFICATION_FAILED';
    const custodyDetails = {
      action: verification.matched ? 'Scheduled Cryptographic Hash Match Verification' : 'CRITICAL INTEGRITY FAILURE DETECTED',
      recorded_sha256: evidence.original_sha256,
      calculated_sha256: verification.calculatedSha256,
      matched: verification.matched,
      file_size_bytes: verification.fileSizeBytes,
      message: verification.message,
    };

    const insertCustody = db.prepare(`
      INSERT INTO custody_events (
        id, evidence_id, action, actor_id, actor_name, actor_role, timestamp_utc, details_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insertCustody.run(
      custodyEventId,
      id,
      custodyAction,
      req.user!.id,
      req.user!.full_name,
      req.user!.role,
      now,
      JSON.stringify(custodyDetails),
      now
    );

    // Append to Audit Log
    appendAuditLog({
      actorId: req.user!.id,
      actorName: req.user!.full_name,
      actorRole: req.user!.role,
      action: verification.matched ? 'INTEGRITY_VERIFIED_MATCH' : 'SECURITY_INCIDENT_INTEGRITY_FAILURE',
      evidenceId: id,
      details: {
        recorded_sha256: evidence.original_sha256,
        live_calculated_sha256: verification.calculatedSha256,
        status: newStatus,
        case_id: evidence.case_id,
      },
    });

    res.json({
      evidenceId: id,
      status: newStatus,
      matched: verification.matched,
      originalSha256: evidence.original_sha256,
      liveCalculatedSha256: verification.calculatedSha256,
      verifiedAt: now,
      message: verification.message,
    });
  } catch (err: unknown) {
    console.error('Integrity verification error:', err);
    res.status(500).json({ error: 'Integrity check failed: ' + (err instanceof Error ? err.message : String(err)) });
  }
});

// Secure Download Endpoint (BLOCKED IF VERIFICATION FAILS)
evidenceRouter.get('/download/:id', requireAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const { id } = req.params;

    const stmt = db.prepare('SELECT * FROM evidence WHERE id = ?');
    const evidence = stmt.get(id) as EvidenceRow | undefined;

    if (!evidence) {
      res.status(404).json({ error: 'Evidence record not found.' });
      return;
    }

    const now = new Date().toISOString();

    // MANDATORY SECURITY GATE: Re-calculate SHA-256 before releasing bytes
    const verification = await verifyEvidenceIntegrity(evidence.storage_filename, evidence.original_sha256);

    if (!verification.matched) {
      // Record download blocked incident
      const custodyEventId = `CST-${crypto.randomUUID()}`;
      db.prepare(`
        INSERT INTO custody_events (
          id, evidence_id, action, actor_id, actor_name, actor_role, timestamp_utc, details_json, created_at
        ) VALUES (?, ?, 'DOWNLOAD_BLOCKED', ?, ?, ?, ?, ?, ?)
      `).run(
        custodyEventId,
        id,
        req.user!.id,
        req.user!.full_name,
        req.user!.role,
        now,
        JSON.stringify({
          reason: 'Download blocked due to cryptographic hash mismatch (tampered evidence)',
          recorded_sha256: evidence.original_sha256,
          calculated_sha256: verification.calculatedSha256,
        }),
        now
      );

      appendAuditLog({
        actorId: req.user!.id,
        actorName: req.user!.full_name,
        actorRole: req.user!.role,
        action: 'DOWNLOAD_BLOCKED_TAMPER_DETECTED',
        evidenceId: id,
        details: {
          attempted_by: req.user!.username,
          recorded_sha256: evidence.original_sha256,
          calculated_sha256: verification.calculatedSha256,
        },
      });

      res.status(403).json({
        error: 'DOWNLOAD FORBIDDEN: Evidence failed cryptographic integrity verification. Download is blocked to preserve forensic integrity.',
        status: verification.status,
        originalSha256: evidence.original_sha256,
        calculatedSha256: verification.calculatedSha256,
      });
      return;
    }

    // Record authorized download custody event
    const custodyEventId = `CST-${crypto.randomUUID()}`;
    db.prepare(`
      INSERT INTO custody_events (
        id, evidence_id, action, actor_id, actor_name, actor_role, timestamp_utc, details_json, created_at
      ) VALUES (?, ?, 'DOWNLOAD_SUCCESS', ?, ?, ?, ?, ?, ?)
    `).run(
      custodyEventId,
      id,
      req.user!.id,
      req.user!.full_name,
      req.user!.role,
      now,
      JSON.stringify({
        action: 'Authorized forensic export/download',
        integrity_status: 'VERIFIED_MATCH',
      }),
      now
    );

    appendAuditLog({
      actorId: req.user!.id,
      actorName: req.user!.full_name,
      actorRole: req.user!.role,
      action: 'EVIDENCE_DOWNLOADED',
      evidenceId: id,
      details: {
        filename: evidence.original_filename,
        sha256: evidence.original_sha256,
      },
    });

    const targetPath = resolveSafePath(evidence.storage_filename);
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(evidence.original_filename)}"`);
    res.setHeader('Content-Type', evidence.mime_type);
    fs.createReadStream(targetPath).pipe(res);
  } catch (err: unknown) {
    console.error('Evidence download error:', err);
    res.status(500).json({ error: 'Download failed: ' + (err instanceof Error ? err.message : String(err)) });
  }
});

// Forensic PDF Report Generation
evidenceRouter.get('/report/:id', requireAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const { id } = req.params;

    const stmt = db.prepare('SELECT * FROM evidence WHERE id = ?');
    const evidence = stmt.get(id) as EvidenceRow | undefined;

    if (!evidence) {
      res.status(404).json({ error: 'Evidence record not found.' });
      return;
    }

    const now = new Date().toISOString();

    const pdfBuffer = await generateEvidencePdfReport(evidence);

    // Record report generation in custody log
    const custodyEventId = `CST-${crypto.randomUUID()}`;
    db.prepare(`
      INSERT INTO custody_events (
        id, evidence_id, action, actor_id, actor_name, actor_role, timestamp_utc, details_json, created_at
      ) VALUES (?, ?, 'REPORT_GENERATED', ?, ?, ?, ?, ?, ?)
    `).run(
      custodyEventId,
      id,
      req.user!.id,
      req.user!.full_name,
      req.user!.role,
      now,
      JSON.stringify({
        report_type: 'Forensic Evidence Certificate & Chain of Custody PDF',
        generated_by: req.user!.full_name,
      }),
      now
    );

    appendAuditLog({
      actorId: req.user!.id,
      actorName: req.user!.full_name,
      actorRole: req.user!.role,
      action: 'FORENSIC_REPORT_GENERATED',
      evidenceId: id,
      details: {
        report_format: 'PDF',
        case_id: evidence.case_id,
      },
    });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="DEIV-Report-${evidence.id}.pdf"`);
    res.send(pdfBuffer);
  } catch (err: unknown) {
    console.error('PDF report error:', err);
    res.status(500).json({ error: 'Failed to generate PDF report: ' + (err instanceof Error ? err.message : String(err)) });
  }
});

// Custody Transfer Record (Investigator or Admin)
evidenceRouter.post(
  '/transfer/:id',
  requireAuth,
  requireRole('Administrator', 'Investigator'),
  (req: AuthenticatedRequest, res: Response): void => {
    const { id } = req.params;
    const { recipient_name, recipient_role, reason } = req.body;

    if (!recipient_name || !recipient_role || !reason) {
      res.status(400).json({ error: 'Recipient name, role/agency, and transfer reason are required.' });
      return;
    }

    const stmt = db.prepare('SELECT * FROM evidence WHERE id = ?');
    const evidence = stmt.get(id) as EvidenceRow | undefined;

    if (!evidence) {
      res.status(404).json({ error: 'Evidence record not found.' });
      return;
    }

    const now = new Date().toISOString();
    const custodyEventId = `CST-${crypto.randomUUID()}`;

    db.prepare(`
      INSERT INTO custody_events (
        id, evidence_id, action, actor_id, actor_name, actor_role, timestamp_utc, details_json, created_at
      ) VALUES (?, ?, 'CUSTODY_TRANSFER', ?, ?, ?, ?, ?, ?)
    `).run(
      custodyEventId,
      id,
      req.user!.id,
      req.user!.full_name,
      req.user!.role,
      now,
      JSON.stringify({
        action: 'Official Chain of Custody Transfer',
        transferred_to: recipient_name.trim(),
        recipient_agency_or_role: recipient_role.trim(),
        justification: reason.trim(),
      }),
      now
    );

    appendAuditLog({
      actorId: req.user!.id,
      actorName: req.user!.full_name,
      actorRole: req.user!.role,
      action: 'CUSTODY_TRANSFERRED',
      evidenceId: id,
      details: {
        transferred_to: recipient_name.trim(),
        recipient_role: recipient_role.trim(),
        case_id: evidence.case_id,
        reason: reason.trim(),
      },
    });

    res.json({ message: 'Chain of custody transfer successfully recorded.', eventId: custodyEventId });
  }
);

// Educational Demonstration Utility: Invert byte or restore file
evidenceRouter.post(
  '/tamper-demo/:id',
  requireAuth,
  requireRole('Administrator', 'Investigator'),
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { id } = req.params;
      const { action } = req.body; // 'tamper' | 'restore'

      const stmt = db.prepare('SELECT * FROM evidence WHERE id = ?');
      const evidence = stmt.get(id) as EvidenceRow | undefined;

      if (!evidence) {
        res.status(404).json({ error: 'Evidence record not found.' });
        return;
      }

      const now = new Date().toISOString();

      if (action === 'tamper') {
        await injectTampering(evidence.storage_filename);
        db.prepare('UPDATE evidence SET is_tampered_demo = 1 WHERE id = ?').run(id);

        appendAuditLog({
          actorId: req.user!.id,
          actorName: req.user!.full_name,
          actorRole: req.user!.role,
          action: 'DEMO_TAMPER_SIMULATION_INJECTED',
          evidenceId: id,
          details: {
            simulation_note: 'Educational demonstration: 1-byte alteration injected into raw vault file on disk.',
          },
        });

        res.json({
          message: 'Educational Simulation: 1 byte has been altered in the stored file on disk. Run Verify Integrity now to observe SHA-256 mismatch detection!',
          isTamperedDemo: 1,
        });
      } else {
        await restorePristineFile(evidence.storage_filename);
        db.prepare('UPDATE evidence SET is_tampered_demo = 0 WHERE id = ?').run(id);

        appendAuditLog({
          actorId: req.user!.id,
          actorName: req.user!.full_name,
          actorRole: req.user!.role,
          action: 'DEMO_TAMPER_SIMULATION_RESTORED',
          evidenceId: id,
          details: {
            simulation_note: 'Educational demonstration: Pristine byte backup restored.',
          },
        });

        res.json({
          message: 'Evidence file restored to original pristine state from secure backup.',
          isTamperedDemo: 0,
        });
      }
    } catch (err: unknown) {
      console.error('Tamper demo error:', err);
      res.status(500).json({ error: 'Tamper simulation failed: ' + (err instanceof Error ? err.message : String(err)) });
    }
  }
);
