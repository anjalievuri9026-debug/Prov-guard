import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { initDatabase, db, appendAuditLog } from './server/db.js';
import { authMiddleware } from './server/middleware/auth.js';
import { authRouter } from './server/routes/auth.js';
import { evidenceRouter } from './server/routes/evidence.js';
import { auditRouter } from './server/routes/audit.js';
import { statsRouter } from './server/routes/stats.js';
import { saveEvidenceFile } from './server/storage.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

import { securityHeadersMiddleware } from './server/middleware/security.js';

// Security & Parsing Middlewares
app.use(securityHeadersMiddleware);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Attach user session from token/cookie
app.use(authMiddleware);

// API Routes
app.use('/api/auth', authRouter);
app.use('/api/evidence', evidenceRouter);
app.use('/api/audit', auditRouter);
app.use('/api/stats', statsRouter);

// Health check endpoint
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'online',
    system: 'Digital Evidence Integrity Vault (DEIV)',
    time: new Date().toISOString(),
    cryptoEngine: 'Node.js Cryptography Suite v22',
  });
});

// Seed Synthetic Evidence if vault is empty
async function seedSyntheticEvidence() {
  const countStmt = db.prepare('SELECT COUNT(*) as count FROM evidence');
  const count = (countStmt.get() as { count: number }).count;

  if (count === 0) {
    console.log('[DEIV] Ingesting initial synthetic baseline evidence records...');
    const now = new Date().toISOString();

    // Sample 1: Memory Dump Extract
    const sample1Content = Buffer.from('--- DEIV SYNTHETIC FORENSIC MEMORY DUMP ---\nProcess: svchost.exe [PID 1044]\nNetwork Socket: 198.51.100.23:443 -> ESTABLISHED\nAllocated Virtual Address: 0x7FFA89B00000\nStatus: Acquired during incident triage.\n', 'utf-8');
    const storage1 = 'sample-memory-dump-01.raw';
    const { fileSizeBytes: size1, calculatedSha256: sha1 } = await saveEvidenceFile(sample1Content, storage1);

    const ev1Id = 'EVD-2026-00101';
    db.prepare(`
      INSERT INTO evidence (
        id, case_id, title, original_filename, storage_filename, mime_type,
        file_size_bytes, original_sha256, uploader_id, uploader_name, uploader_role,
        created_at, status, last_verified_at, last_calculated_sha256, notes, tags
      ) VALUES (?, 'CASE-2026-ALPHA', 'Suspect RAM Capture Segment', 'memory_dump_core.raw', ?, 'application/octet-stream', ?, ?, 'usr-inv-01', 'Detective Sarah Chen', 'Investigator', ?, 'VERIFIED', ?, ?, 'Live RAM acquisition from endpoint workstation during Incident Alpha-12. Clearly marked synthetic college project test data.', 'volatile_memory,endpoint,triage')
    `).run(ev1Id, storage1, size1, sha1, now, now, sha1);

    db.prepare(`
      INSERT INTO custody_events (
        id, evidence_id, action, actor_id, actor_name, actor_role, timestamp_utc, details_json, created_at
      ) VALUES ('CST-SEED-01', ?, 'INGESTION', 'usr-inv-01', 'Detective Sarah Chen', 'Investigator', ?, ?, ?)
    `).run(
      ev1Id,
      now,
      JSON.stringify({
        action: 'Initial acquisition from incident workstation',
        sha256: sha1,
        source: 'Forensic Write Blocker Model FTK-4',
      }),
      now
    );

    appendAuditLog({
      actorId: 'usr-inv-01',
      actorName: 'Detective Sarah Chen',
      actorRole: 'Investigator',
      action: 'EVIDENCE_INGESTED',
      evidenceId: ev1Id,
      details: {
        case_id: 'CASE-2026-ALPHA',
        filename: 'memory_dump_core.raw',
        sha256: sha1,
        synthetic_sample: true,
      },
    });

    // Sample 2: Network Packet Capture Extract
    const sample2Content = Buffer.from('--- DEIV SYNTHETIC NETWORK PCAP EXCERPT ---\nFRAME 1: 192.168.1.100 -> 198.51.100.42 PROTO TCP [SYN] SEQ=0\nFRAME 2: 198.51.100.42 -> 192.168.1.100 PROTO TCP [SYN, ACK] SEQ=0 ACK=1\nFRAME 3: 192.168.1.100 -> 198.51.100.42 PROTO TCP [ACK] SEQ=1 ACK=1\n', 'utf-8');
    const storage2 = 'sample-network-trace-02.pcap';
    const { fileSizeBytes: size2, calculatedSha256: sha2 } = await saveEvidenceFile(sample2Content, storage2);

    const ev2Id = 'EVD-2026-00102';
    db.prepare(`
      INSERT INTO evidence (
        id, case_id, title, original_filename, storage_filename, mime_type,
        file_size_bytes, original_sha256, uploader_id, uploader_name, uploader_role,
        created_at, status, last_verified_at, last_calculated_sha256, notes, tags
      ) VALUES (?, 'CASE-2026-BETA', 'Perimeter Firewall Exfiltration Capture', 'firewall_ingress_trace.pcap', ?, 'application/vnd.tcpdump.pcap', ?, ?, 'usr-admin-01', 'Chief Security Officer', 'Administrator', ?, 'VERIFIED', ?, ?, 'Intercepted outbound traffic stream. Synthetic demo artifact for integrity testing.', 'network,pcap,firewall')
    `).run(ev2Id, storage2, size2, sha2, now, now, sha2);

    db.prepare(`
      INSERT INTO custody_events (
        id, evidence_id, action, actor_id, actor_name, actor_role, timestamp_utc, details_json, created_at
      ) VALUES ('CST-SEED-02', ?, 'INGESTION', 'usr-admin-01', 'Chief Security Officer', 'Administrator', ?, ?, ?)
    `).run(
      ev2Id,
      now,
      JSON.stringify({
        action: 'Acquired from perimeter firewall sensor mirror port',
        sha256: sha2,
      }),
      now
    );

    appendAuditLog({
      actorId: 'usr-admin-01',
      actorName: 'Chief Security Officer',
      actorRole: 'Administrator',
      action: 'EVIDENCE_INGESTED',
      evidenceId: ev2Id,
      details: {
        case_id: 'CASE-2026-BETA',
        filename: 'firewall_ingress_trace.pcap',
        sha256: sha2,
        synthetic_sample: true,
      },
    });

    console.log('[DEIV] Synthetic evidence seed complete.');
  }
}

async function startServer() {
  initDatabase();
  await seedSyntheticEvidence();

  const isProduction = process.env.NODE_ENV === 'production';

  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[DEIV] Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[DEIV] Fatal startup failure:', err);
  process.exit(1);
});
