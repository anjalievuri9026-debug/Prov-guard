import PDFDocument from 'pdfkit';
import { EvidenceRow, CustodyEventRow, db } from './db.js';
import { verifyEvidenceIntegrity } from './storage.js';

export async function generateEvidencePdfReport(evidence: EvidenceRow): Promise<Buffer> {
  // Re-verify live integrity directly before generating report to guarantee fresh forensic proof
  const liveVerification = await verifyEvidenceIntegrity(evidence.storage_filename, evidence.original_sha256);

  // Fetch all custody events for this evidence in chronological order
  const custodyStmt = db.prepare('SELECT * FROM custody_events WHERE evidence_id = ? ORDER BY timestamp_utc ASC');
  const custodyEvents = custodyStmt.all(evidence.id) as unknown as CustodyEventRow[];

  // Fetch relevant audit log entries
  const auditStmt = db.prepare('SELECT sequence_num, current_entry_hash, timestamp_utc FROM audit_log WHERE evidence_id = ? ORDER BY sequence_num ASC');
  const auditEntries = auditStmt.all(evidence.id) as unknown as { sequence_num: number; current_entry_hash: string; timestamp_utc: string }[];

  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        margin: 40,
        size: 'A4',
        info: {
          Title: `Forensic Evidence Certificate - ${evidence.id}`,
          Author: 'DEIV - Digital Evidence Integrity Vault',
          Subject: `Cryptographic Integrity & Chain of Custody Report: Case ${evidence.case_id}`,
          Keywords: 'Forensics, SHA-256, Chain of Custody, DEIV, Evidence',
        },
      });

      const buffers: Buffer[] = [];
      doc.on('data', (chunk) => buffers.push(chunk));
      doc.on('end', () => resolve(Buffer.concat(buffers)));
      doc.on('error', (err) => reject(err));

      // Header Banner
      doc.rect(40, 40, doc.page.width - 80, 65).fill('#0f172a');

      doc.fillColor('#06b6d4').fontSize(18).font('Helvetica-Bold')
        .text('DIGITAL EVIDENCE INTEGRITY VAULT (DEIV)', 55, 52);
      doc.fillColor('#94a3b8').fontSize(9).font('Helvetica')
        .text('FORENSIC EVIDENCE CERTIFICATE & CHAIN OF CUSTODY REPORT', 55, 75);
      doc.fillColor('#38bdf8').fontSize(8).font('Helvetica')
        .text(`Generated: ${new Date().toISOString()}`, doc.page.width - 240, 75, { align: 'right' });

      doc.moveDown(4);

      // Status Badge
      const isVerified = liveVerification.matched;
      const statusColor = isVerified ? '#10b981' : '#ef4444';
      const statusBg = isVerified ? '#064e3b' : '#7f1d1d';
      const statusText = isVerified ? 'CRYPTOGRAPHIC INTEGRITY: VERIFIED MATCH' : 'ALERT: INTEGRITY FAILURE / TAMPER DETECTED';

      const badgeY = 120;
      doc.rect(40, badgeY, doc.page.width - 80, 26).fill(statusBg);
      doc.fillColor(statusColor).fontSize(10).font('Helvetica-Bold')
        .text(statusText, 55, badgeY + 8);

      // Section 1: Evidence Identification
      doc.moveDown(2);
      const startY = badgeY + 40;
      doc.fillColor('#0f172a').fontSize(12).font('Helvetica-Bold').text('1. EVIDENCE SPECIFICATION & INGESTION RECORD', 40, startY);
      doc.rect(40, startY + 16, doc.page.width - 80, 1).fill('#cbd5e1');

      let currentY = startY + 25;
      const addMetaRow = (label: string, value: string, mono = false) => {
        doc.fillColor('#475569').fontSize(9).font('Helvetica-Bold').text(label, 50, currentY, { width: 140 });
        doc.fillColor('#0f172a').fontSize(9).font(mono ? 'Courier' : 'Helvetica').text(value, 200, currentY, { width: doc.page.width - 250 });
        currentY += 16;
      };

      addMetaRow('Evidence Identifier:', evidence.id);
      addMetaRow('Case File Reference:', evidence.case_id);
      addMetaRow('Evidence Title:', evidence.title);
      addMetaRow('Original Filename:', evidence.original_filename);
      addMetaRow('File Size (Ingestion):', `${evidence.file_size_bytes.toLocaleString()} bytes`);
      addMetaRow('MIME Classification:', evidence.mime_type);
      addMetaRow('Ingested By:', `${evidence.uploader_name} (${evidence.uploader_role})`);
      addMetaRow('Ingestion Timestamp (UTC):', evidence.created_at);

      // Section 2: Cryptographic Hash Verification
      currentY += 10;
      doc.fillColor('#0f172a').fontSize(12).font('Helvetica-Bold').text('2. CRYPTOGRAPHIC INTEGRITY VERIFICATION (SHA-256)', 40, currentY);
      doc.rect(40, currentY + 16, doc.page.width - 80, 1).fill('#cbd5e1');

      currentY += 25;
      addMetaRow('Recorded Ingestion Hash:', evidence.original_sha256, true);
      addMetaRow('Live Disk Calculated Hash:', liveVerification.calculatedSha256 || 'N/A (File Missing)', true);
      addMetaRow('Integrity Status:', isVerified ? 'VALID MATCH (0 discrepancies)' : 'TAMPER DETECTED / MISMATCH');
      addMetaRow('Verification Engine:', 'Node.js Crypto SHA-256 Streaming Byte Digest');

      // Section 3: Chronological Chain of Custody
      currentY += 15;
      doc.fillColor('#0f172a').fontSize(12).font('Helvetica-Bold').text('3. CHRONOLOGICAL CHAIN OF CUSTODY LOG', 40, currentY);
      doc.rect(40, currentY + 16, doc.page.width - 80, 1).fill('#cbd5e1');

      currentY += 22;
      // Table Header
      doc.rect(40, currentY, doc.page.width - 80, 18).fill('#f1f5f9');
      doc.fillColor('#334155').fontSize(8).font('Helvetica-Bold');
      doc.text('TIMESTAMP (UTC)', 45, currentY + 5, { width: 120 });
      doc.text('ACTION', 170, currentY + 5, { width: 110 });
      doc.text('OFFICER / ACTOR', 285, currentY + 5, { width: 110 });
      doc.text('DETAILS / RECORD', 400, currentY + 5, { width: 150 });

      currentY += 20;

      for (const event of custodyEvents) {
        if (currentY > doc.page.height - 100) {
          doc.addPage();
          currentY = 50;
        }

        let detailsParsed = event.details_json;
        try {
          const parsed = JSON.parse(event.details_json);
          detailsParsed = typeof parsed === 'object' ? Object.entries(parsed).map(([k, v]) => `${k}: ${v}`).join('; ') : String(parsed);
        } catch {
          // keep as string
        }

        doc.fillColor('#475569').fontSize(7.5).font('Courier').text(event.timestamp_utc.slice(0, 19), 45, currentY, { width: 120 });
        doc.fillColor('#0f172a').fontSize(8).font('Helvetica-Bold').text(event.action, 170, currentY, { width: 110 });
        doc.fillColor('#334155').fontSize(8).font('Helvetica').text(`${event.actor_name} (${event.actor_role})`, 285, currentY, { width: 110 });
        doc.fillColor('#475569').fontSize(7.5).font('Helvetica').text(detailsParsed, 400, currentY, { width: 150 });

        currentY += 20;
        doc.rect(40, currentY - 4, doc.page.width - 80, 0.5).fill('#e2e8f0');
      }

      // Section 4: Audit Trail Anchor & Legal Notice
      if (currentY > doc.page.height - 120) {
        doc.addPage();
        currentY = 50;
      } else {
        currentY += 15;
      }

      doc.fillColor('#0f172a').fontSize(11).font('Helvetica-Bold').text('4. AUDIT CHAIN REFERENCES & FORENSIC ATTESTATION', 40, currentY);
      doc.rect(40, currentY + 15, doc.page.width - 80, 1).fill('#cbd5e1');

      currentY += 22;
      doc.fillColor('#64748b').fontSize(7.5).font('Helvetica')
        .text('Forensic Notice: This certificate reflects server-verified cryptographic hash matching calculated directly from raw byte streams in private vault storage. Tamper-evident audit chain linkage guarantees that any log alterations are detectable. Note: local cryptographic hash chaining is tamper-evident, not inherently immutable against authorized storage rewrites without external timestamping anchors.', 45, currentY, { width: doc.page.width - 90, align: 'justify' });

      currentY += 35;
      if (auditEntries.length > 0) {
        const latestAudit = auditEntries[auditEntries.length - 1];
        doc.fillColor('#0f172a').fontSize(8).font('Helvetica-Bold')
          .text(`Latest Linked Audit Sequence: #${latestAudit.sequence_num}`, 45, currentY);
        doc.fillColor('#475569').fontSize(7.5).font('Courier')
          .text(`Audit Node Hash: ${latestAudit.current_entry_hash}`, 45, currentY + 12);
      }

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}
