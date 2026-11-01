import { Router, Response } from 'express';
import { db, verifyAuditChain, AuditLogRow, appendAuditLog } from '../db.js';
import { AuthenticatedRequest, requireAuth, requireRole } from '../middleware/auth.js';

export const auditRouter = Router();

// Retrieve audit logs with pagination and filtering
auditRouter.get('/logs', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  const { limit = '50', offset = '0', action, evidence_id } = req.query;

  let query = 'SELECT * FROM audit_log WHERE 1=1';
  const params: (string | number)[] = [];

  if (action && typeof action === 'string' && action.trim() !== '') {
    query += ' AND action = ?';
    params.push(action.trim());
  }

  if (evidence_id && typeof evidence_id === 'string' && evidence_id.trim() !== '') {
    query += ' AND evidence_id = ?';
    params.push(evidence_id.trim());
  }

  query += ' ORDER BY sequence_num DESC LIMIT ? OFFSET ?';
  params.push(Math.min(parseInt(limit as string, 10) || 50, 200), parseInt(offset as string, 10) || 0);

  const stmt = db.prepare(query);
  const logs = stmt.all(...params) as unknown as AuditLogRow[];

  const countStmt = db.prepare('SELECT COUNT(*) as total FROM audit_log');
  const count = (countStmt.get() as { total: number }).total;

  res.json({
    logs,
    total: count,
  });
});

// Full Cryptographic Audit Chain Verification
auditRouter.post('/verify-chain', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  const result = verifyAuditChain();

  // Record chain audit action
  appendAuditLog({
    actorId: req.user!.id,
    actorName: req.user!.full_name,
    actorRole: req.user!.role,
    action: result.isValid ? 'AUDIT_CHAIN_VERIFIED_INTACT' : 'AUDIT_CHAIN_INTEGRITY_BREACH_DETECTED',
    evidenceId: null,
    details: {
      verified_by: req.user!.username,
      total_entries: result.totalEntries,
      is_valid: result.isValid,
      broken_at_sequence: result.brokenAtSequence || null,
      discrepancy: result.reason || 'All cryptographic hash linkages match.',
    },
  });

  res.json(result);
});

// Educational Simulation Utility: Tamper with audit log row to test chain detection
auditRouter.post(
  '/tamper-demo',
  requireAuth,
  requireRole('Administrator'),
  (req: AuthenticatedRequest, res: Response): void => {
    const { sequence_num, action } = req.body;

    if (action === 'tamper') {
      const targetSeq = parseInt(sequence_num as string, 10) || 1;
      const targetStmt = db.prepare('SELECT * FROM audit_log WHERE sequence_num = ?');
      const target = targetStmt.get(targetSeq) as AuditLogRow | undefined;

      if (!target) {
        res.status(404).json({ error: `Audit sequence #${targetSeq} not found.` });
        return;
      }

      // Alter the action string without recalculating the hash, simulating unauthorized database alteration
      db.prepare(`
        UPDATE audit_log
        SET action = action || '_UNAUTHORIZED_ALTERATION'
        WHERE sequence_num = ?
      `).run(targetSeq);

      res.json({
        message: `Educational Simulation: Audit record #${targetSeq} was modified directly in the database without updating its cryptographic hash. Run Verify Audit Chain now to see the detection algorithm catch it!`,
        tamperedSequence: targetSeq,
      });
    } else if (action === 'restore') {
      // Revert the alteration
      db.prepare(`
        UPDATE audit_log
        SET action = REPLACE(action, '_UNAUTHORIZED_ALTERATION', '')
        WHERE action LIKE '%_UNAUTHORIZED_ALTERATION'
      `).run();

      res.json({
        message: 'Audit log record restored to canonical state.',
      });
    } else {
      res.status(400).json({ error: "Invalid action. Use 'tamper' or 'restore'." });
    }
  }
);
