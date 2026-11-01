import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { GENESIS_HASH, hashPassword, calculateEntryHash, canonicalize, sha256 } from './crypto.js';
import { getServerSigningKey } from './provguard/keys.js';
import { MOCK_TSA_CERT_ID, MOCK_TSA_PUBLIC_KEY_PEM, MOCK_TSA_NAME } from './provguard/timestamp.js';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'deiv.db');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

export const db = new DatabaseSync(DB_FILE);

// Enable WAL mode for high concurrent read/write throughput and ACID reliability
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');
db.exec('PRAGMA synchronous = NORMAL;');

export interface UserRow {
  id: string;
  username: string;
  email: string;
  full_name: string;
  role: 'Administrator' | 'Investigator' | 'Auditor';
  password_hash: string;
  password_salt: string;
  is_active: number;
  created_at: string;
  updated_at: string;
}

export interface SessionRow {
  token: string;
  user_id: string;
  expires_at: string;
  created_at: string;
}

export interface EvidenceRow {
  id: string;
  case_id: string;
  title: string;
  original_filename: string;
  storage_filename: string;
  mime_type: string;
  file_size_bytes: number;
  original_sha256: string;
  uploader_id: string;
  uploader_name: string;
  uploader_role: string;
  created_at: string;
  status: 'VERIFIED' | 'TAMPER_DETECTED' | 'UNVERIFIED' | 'MISSING_FILE' | 'VERIFICATION_FAILED';
  last_verified_at: string | null;
  last_calculated_sha256: string | null;
  notes: string;
  tags: string;
  is_tampered_demo: number;
}

export interface CustodyEventRow {
  id: string;
  evidence_id: string;
  action: string;
  actor_id: string;
  actor_name: string;
  actor_role: string;
  timestamp_utc: string;
  details_json: string;
  created_at: string;
}

export interface AuditLogRow {
  id: number;
  event_id: string;
  sequence_num: number;
  actor_id: string;
  actor_name: string;
  actor_role: string;
  action: string;
  evidence_id: string | null;
  timestamp_utc: string;
  details_canonical: string;
  prev_entry_hash: string;
  current_entry_hash: string;
}

export interface AcquisitionManifestRow {
  id: string;
  evidence_id: string;
  schema_version: string;
  canonical_json: string;
  manifest_sha256: string;
  signature_algorithm: string;
  signer_key_id: string;
  signature_base64: string;
  created_at_utc: string;
}

export interface TrustedSigningKeyRow {
  key_id: string;
  public_key_pem: string;
  owner_label: string;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  valid_from_utc: string;
  valid_until_utc: string | null;
  revoked_at_utc: string | null;
  created_at_utc: string;
}

export interface MerkleTreeRow {
  id: string;
  evidence_id: string;
  format_version: string;
  chunk_size_bytes: number;
  file_size_bytes: number;
  leaf_count: number;
  root_hash: string;
  created_at_utc: string;
}

export interface MerkleLeafRow {
  tree_id: string;
  leaf_index: number;
  chunk_size_bytes: number;
  leaf_hash: string;
}

export interface ArtifactNodeRow {
  artifact_id: string;
  evidence_id: string;
  sha256: string;
  size_bytes: number;
  created_at_utc: string;
  description: string;
}

export interface ArtifactParentRow {
  child_artifact_id: string;
  parent_artifact_id: string;
}

export interface TransformationRow {
  id: string;
  child_artifact_id: string;
  tool_name: string;
  tool_version: string;
  parameters_canonical: string;
  operator_id: string;
  performed_at_utc: string;
  signature_key_id: string | null;
  signature_base64: string | null;
}

export interface ContextObservationRow {
  id: string;
  evidence_id: string;
  label: string;
  value_utc: string;
  source_type: 'embedded' | 'operator' | 'server' | 'trusted_timestamp' | 'external' | 'unknown';
  source_reference: string;
  uncertainty_ms: number;
  created_at_utc: string;
}

export interface ContextFindingRow {
  id: string;
  evidence_id: string;
  rule_id: string;
  status: 'CONSISTENT' | 'CONFLICT' | 'AMBIGUOUS' | 'UNKNOWN';
  explanation: string;
  conflicting_observations_json: string;
  review_state: 'PENDING' | 'INVESTIGATING' | 'RESOLVED' | 'ACCEPTED_RISK';
  reviewer_id: string | null;
  reviewed_at_utc: string | null;
  created_at_utc: string;
}

export interface AuditCheckpointRow {
  id: string;
  audit_sequence: number;
  audit_head_hash: string;
  created_at_utc: string;
  signer_key_id: string;
  signature_base64: string;
  external_anchor_reference: string | null;
}

export interface TimestampTokenRow {
  id: string;
  evidence_id: string;
  imprint_sha256: string;
  token_der_base64: string;
  tsa_certificate_id: string;
  verification_status: 'VERIFIED' | 'NOT_CONFIGURED' | 'UNKNOWN' | 'INVALID';
  verified_at_utc: string | null;
  created_at_utc: string;
}

// Initialize tables and indexes
export function initDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      full_name TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('Administrator', 'Investigator', 'Auditor')),
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS evidence (
      id TEXT PRIMARY KEY,
      case_id TEXT NOT NULL,
      title TEXT NOT NULL,
      original_filename TEXT NOT NULL,
      storage_filename TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      file_size_bytes INTEGER NOT NULL,
      original_sha256 TEXT NOT NULL,
      uploader_id TEXT NOT NULL REFERENCES users(id),
      uploader_name TEXT NOT NULL,
      uploader_role TEXT NOT NULL,
      created_at TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'UNVERIFIED' CHECK(status IN ('VERIFIED', 'TAMPER_DETECTED', 'UNVERIFIED', 'MISSING_FILE', 'VERIFICATION_FAILED')),
      last_verified_at TEXT,
      last_calculated_sha256 TEXT,
      notes TEXT DEFAULT '',
      tags TEXT DEFAULT '',
      is_tampered_demo INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
    CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence(original_sha256);
    CREATE INDEX IF NOT EXISTS idx_evidence_status ON evidence(status);

    CREATE TABLE IF NOT EXISTS custody_events (
      id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      action TEXT NOT NULL,
      actor_id TEXT NOT NULL,
      actor_name TEXT NOT NULL,
      actor_role TEXT NOT NULL,
      timestamp_utc TEXT NOT NULL,
      details_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_custody_evidence ON custody_events(evidence_id);

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id TEXT UNIQUE NOT NULL,
      sequence_num INTEGER NOT NULL,
      actor_id TEXT NOT NULL,
      actor_name TEXT NOT NULL,
      actor_role TEXT NOT NULL,
      action TEXT NOT NULL,
      evidence_id TEXT,
      timestamp_utc TEXT NOT NULL,
      details_canonical TEXT NOT NULL,
      prev_entry_hash TEXT NOT NULL,
      current_entry_hash TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_log(sequence_num);
    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

    -- PROV-GUARD: Acquisition Manifests
    CREATE TABLE IF NOT EXISTS acquisition_manifests (
      id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      schema_version TEXT NOT NULL DEFAULT 'PROVGUARD_ACQUISITION_V1',
      canonical_json TEXT NOT NULL,
      manifest_sha256 TEXT NOT NULL,
      signature_algorithm TEXT NOT NULL DEFAULT 'Ed25519',
      signer_key_id TEXT NOT NULL,
      signature_base64 TEXT NOT NULL,
      created_at_utc TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_manifest_evidence ON acquisition_manifests(evidence_id);

    -- PROV-GUARD: Trusted Signing Keys Registry
    CREATE TABLE IF NOT EXISTS trusted_signing_keys (
      key_id TEXT PRIMARY KEY,
      public_key_pem TEXT NOT NULL,
      owner_label TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
      valid_from_utc TEXT NOT NULL,
      valid_until_utc TEXT,
      revoked_at_utc TEXT,
      created_at_utc TEXT NOT NULL
    );

    -- PROV-GUARD: Merkle Trees & Leaves
    CREATE TABLE IF NOT EXISTS merkle_trees (
      id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      format_version TEXT NOT NULL DEFAULT 'PROVGUARD_MERKLE_V1',
      chunk_size_bytes INTEGER NOT NULL,
      file_size_bytes INTEGER NOT NULL,
      leaf_count INTEGER NOT NULL,
      root_hash TEXT NOT NULL,
      created_at_utc TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_merkle_evidence ON merkle_trees(evidence_id);

    CREATE TABLE IF NOT EXISTS merkle_leaves (
      tree_id TEXT NOT NULL REFERENCES merkle_trees(id) ON DELETE CASCADE,
      leaf_index INTEGER NOT NULL,
      chunk_size_bytes INTEGER NOT NULL,
      leaf_hash TEXT NOT NULL,
      PRIMARY KEY (tree_id, leaf_index)
    );

    -- PROV-GUARD: Evidence Genealogy Artifacts & Edges
    CREATE TABLE IF NOT EXISTS artifact_nodes (
      artifact_id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      sha256 TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      created_at_utc TEXT NOT NULL,
      description TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_artifact_evidence ON artifact_nodes(evidence_id);

    CREATE TABLE IF NOT EXISTS artifact_parents (
      child_artifact_id TEXT NOT NULL REFERENCES artifact_nodes(artifact_id) ON DELETE CASCADE,
      parent_artifact_id TEXT NOT NULL REFERENCES artifact_nodes(artifact_id) ON DELETE CASCADE,
      PRIMARY KEY (child_artifact_id, parent_artifact_id)
    );

    CREATE TABLE IF NOT EXISTS transformations (
      id TEXT PRIMARY KEY,
      child_artifact_id TEXT NOT NULL REFERENCES artifact_nodes(artifact_id) ON DELETE CASCADE,
      tool_name TEXT NOT NULL,
      tool_version TEXT NOT NULL,
      parameters_canonical TEXT NOT NULL,
      operator_id TEXT NOT NULL,
      performed_at_utc TEXT NOT NULL,
      signature_key_id TEXT,
      signature_base64 TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_transformations_child ON transformations(child_artifact_id);

    -- PROV-GUARD: Context Chronology Observations & Contradiction Findings
    CREATE TABLE IF NOT EXISTS context_observations (
      id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      label TEXT NOT NULL,
      value_utc TEXT NOT NULL,
      source_type TEXT NOT NULL CHECK(source_type IN ('embedded', 'operator', 'server', 'trusted_timestamp', 'external', 'unknown')),
      source_reference TEXT,
      uncertainty_ms INTEGER NOT NULL DEFAULT 0,
      created_at_utc TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_observations_evidence ON context_observations(evidence_id);

    CREATE TABLE IF NOT EXISTS context_findings (
      id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      rule_id TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('CONSISTENT', 'CONFLICT', 'AMBIGUOUS', 'UNKNOWN')),
      explanation TEXT NOT NULL,
      conflicting_observations_json TEXT,
      review_state TEXT NOT NULL DEFAULT 'PENDING' CHECK(review_state IN ('PENDING', 'INVESTIGATING', 'RESOLVED', 'ACCEPTED_RISK')),
      reviewer_id TEXT,
      reviewed_at_utc TEXT,
      created_at_utc TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_findings_evidence ON context_findings(evidence_id);

    -- PROV-GUARD: Signed Audit Checkpoints
    CREATE TABLE IF NOT EXISTS audit_checkpoints (
      id TEXT PRIMARY KEY,
      audit_sequence INTEGER NOT NULL,
      audit_head_hash TEXT NOT NULL,
      created_at_utc TEXT NOT NULL,
      signer_key_id TEXT NOT NULL,
      signature_base64 TEXT NOT NULL,
      external_anchor_reference TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_checkpoints_seq ON audit_checkpoints(audit_sequence);

    -- PROV-GUARD: Trusted RFC 3161 Timestamp Tokens
    CREATE TABLE IF NOT EXISTS timestamp_tokens (
      id TEXT PRIMARY KEY,
      evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
      imprint_sha256 TEXT NOT NULL,
      token_der_base64 TEXT NOT NULL,
      tsa_certificate_id TEXT NOT NULL,
      verification_status TEXT NOT NULL CHECK(verification_status IN ('VERIFIED', 'NOT_CONFIGURED', 'UNKNOWN', 'INVALID')),
      verified_at_utc TEXT,
      created_at_utc TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_timestamp_evidence ON timestamp_tokens(evidence_id);
  `);

  seedDefaultUsers();
  seedDefaultTrustedKeys();
}

function seedDefaultTrustedKeys() {
  const serverKey = getServerSigningKey();
  const now = new Date().toISOString();

  // Register server public key
  db.prepare(`
    INSERT OR REPLACE INTO trusted_signing_keys (
      key_id, public_key_pem, owner_label, status, valid_from_utc, valid_until_utc, revoked_at_utc, created_at_utc
    ) VALUES (?, ?, ?, 'ACTIVE', ?, NULL, NULL, ?)
  `).run(serverKey.keyId, serverKey.publicKeyPem, 'PROV-GUARD Core Evidence Server Authority', now, now);

  // Register development mock TSA key
  db.prepare(`
    INSERT OR REPLACE INTO trusted_signing_keys (
      key_id, public_key_pem, owner_label, status, valid_from_utc, valid_until_utc, revoked_at_utc, created_at_utc
    ) VALUES (?, ?, ?, 'ACTIVE', ?, NULL, NULL, ?)
  `).run(MOCK_TSA_CERT_ID, MOCK_TSA_PUBLIC_KEY_PEM, MOCK_TSA_NAME, now, now);
}

function seedDefaultUsers() {
  const countStmt = db.prepare('SELECT COUNT(*) as count FROM users');
  const result = countStmt.get() as { count: number };
  if (result.count === 0) {
    const now = new Date().toISOString();

    const adminAuth = hashPassword('Admin@DEIV2026!');
    const investigatorAuth = hashPassword('Investigator@DEIV2026!');
    const auditorAuth = hashPassword('Auditor@DEIV2026!');

    const insert = db.prepare(`
      INSERT OR IGNORE INTO users (id, username, email, full_name, role, password_hash, password_salt, is_active, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
    `);

    insert.run('usr-admin-01', 'admin', 'admin@deiv.local', 'Chief Security Officer', 'Administrator', adminAuth.hash, adminAuth.salt, now, now);
    insert.run('usr-inv-01', 'investigator', 'investigator@deiv.local', 'Detective Sarah Chen', 'Investigator', investigatorAuth.hash, investigatorAuth.salt, now, now);
    insert.run('usr-aud-01', 'auditor', 'auditor@deiv.local', 'Inspector Marcus Vance', 'Auditor', auditorAuth.hash, auditorAuth.salt, now, now);

    // Initial Genesis Audit Event
    appendAuditLog({
      actorId: 'usr-admin-01',
      actorName: 'Chief Security Officer',
      actorRole: 'Administrator',
      action: 'SYSTEM_GENESIS_INITIALIZATION',
      evidenceId: null,
      details: {
        message: 'Digital Evidence Integrity Vault initialized with cryptographic root',
        version: '1.0.0-forensic',
        system_actor: 'SYSTEM_BOOT',
      },
    });
  }
}

/**
 * Appends a tamper-evident audit log entry linked to the previous entry hash.
 */
export function appendAuditLog(params: {
  actorId: string;
  actorName: string;
  actorRole: string;
  action: string;
  evidenceId: string | null;
  details: unknown;
  timestampUtc?: string;
}): AuditLogRow {
  const timestampUtc = params.timestampUtc || new Date().toISOString();
  const eventId = `EVT-${crypto.randomUUID()}`;

  // Get last entry to fetch sequence_num and prev_entry_hash
  const lastEntryStmt = db.prepare('SELECT sequence_num, current_entry_hash FROM audit_log ORDER BY id DESC LIMIT 1');
  const lastEntry = lastEntryStmt.get() as { sequence_num: number; current_entry_hash: string } | undefined;

  const sequenceNum = lastEntry ? lastEntry.sequence_num + 1 : 1;
  const prevEntryHash = lastEntry ? lastEntry.current_entry_hash : GENESIS_HASH;

  const canonicalDetails = canonicalize(params.details);
  const currentEntryHash = calculateEntryHash(
    prevEntryHash,
    eventId,
    params.action,
    params.actorId,
    timestampUtc,
    params.details
  );

  const insert = db.prepare(`
    INSERT INTO audit_log (
      event_id, sequence_num, actor_id, actor_name, actor_role, action,
      evidence_id, timestamp_utc, details_canonical, prev_entry_hash, current_entry_hash
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insert.run(
    eventId,
    sequenceNum,
    params.actorId,
    params.actorName,
    params.actorRole,
    params.action,
    params.evidenceId,
    timestampUtc,
    canonicalDetails,
    prevEntryHash,
    currentEntryHash
  );

  const getStmt = db.prepare('SELECT * FROM audit_log WHERE event_id = ?');
  return getStmt.get(eventId) as unknown as AuditLogRow;
}

export interface ChainVerificationResult {
  isValid: boolean;
  totalEntries: number;
  genesisHash: string;
  tipHash: string | null;
  verifiedCount: number;
  brokenAtSequence?: number;
  brokenEventId?: string;
  reason?: string;
  discrepancyType?: 'HASH_MISMATCH' | 'PREV_HASH_LINK_BROKEN' | 'SEQUENCE_GAP' | 'GENESIS_TAMPER';
  educationalExplanation: string;
}

/**
 * Validates the entire cryptographic chain from Genesis to tip.
 * Checks:
 * 1. Genesis entry links to standard 0000...0000
 * 2. Strict sequential order (seq = 1, 2, 3...)
 * 3. Each entry's prev_entry_hash matches the previous record's current_entry_hash
 * 4. Each entry's current_entry_hash matches SHA256(prev_hash | eventId | action | actorId | timestamp | canonicalDetails)
 */
export function verifyAuditChain(): ChainVerificationResult {
  const stmt = db.prepare('SELECT * FROM audit_log ORDER BY sequence_num ASC');
  const rows = stmt.all() as unknown as AuditLogRow[];

  const explanation =
    'Cryptographic hash chaining ensures that any retroactive modification, deletion, or insertion of audit entries immediately breaks the subsequent hash links. However, a local hash chain is tamper-evident, not absolutely immutable: an attacker with raw, unconstrained write access to the host storage could mathematically re-compute the entire chain from the point of tampering onwards. Defense-in-depth requires restricted database privileges, independent off-site replication, and external timestamping anchors.';

  if (rows.length === 0) {
    return {
      isValid: true,
      totalEntries: 0,
      genesisHash: GENESIS_HASH,
      tipHash: null,
      verifiedCount: 0,
      educationalExplanation: explanation,
    };
  }

  let expectedPrevHash = GENESIS_HASH;

  for (let i = 0; i < rows.length; i++) {
    const entry = rows[i];
    const expectedSeq = i + 1;

    // Check sequence continuity
    if (entry.sequence_num !== expectedSeq) {
      return {
        isValid: false,
        totalEntries: rows.length,
        genesisHash: GENESIS_HASH,
        tipHash: rows[rows.length - 1].current_entry_hash,
        verifiedCount: i,
        brokenAtSequence: entry.sequence_num,
        brokenEventId: entry.event_id,
        reason: `Sequence break detected: expected sequence #${expectedSeq}, encountered #${entry.sequence_num}`,
        discrepancyType: 'SEQUENCE_GAP',
        educationalExplanation: explanation,
      };
    }

    // Check link to previous hash
    if (entry.prev_entry_hash !== expectedPrevHash) {
      return {
        isValid: false,
        totalEntries: rows.length,
        genesisHash: GENESIS_HASH,
        tipHash: rows[rows.length - 1].current_entry_hash,
        verifiedCount: i,
        brokenAtSequence: entry.sequence_num,
        brokenEventId: entry.event_id,
        reason: `Broken chain link: entry #${entry.sequence_num} links to ${entry.prev_entry_hash.slice(0, 16)}..., but previous entry hash was ${expectedPrevHash.slice(0, 16)}...`,
        discrepancyType: 'PREV_HASH_LINK_BROKEN',
        educationalExplanation: explanation,
      };
    }

    // Re-calculate hash directly from canonical record components
    const recalculatedHash = sha256(
      `${entry.prev_entry_hash}|${entry.event_id}|${entry.action}|${entry.actor_id}|${entry.timestamp_utc}|${entry.details_canonical}`
    );

    if (recalculatedHash !== entry.current_entry_hash) {
      return {
        isValid: false,
        totalEntries: rows.length,
        genesisHash: GENESIS_HASH,
        tipHash: rows[rows.length - 1].current_entry_hash,
        verifiedCount: i,
        brokenAtSequence: entry.sequence_num,
        brokenEventId: entry.event_id,
        reason: `Hash discrepancy detected in entry #${entry.sequence_num}: stored hash is ${entry.current_entry_hash.slice(0, 16)}..., but canonical recalculation produced ${recalculatedHash.slice(0, 16)}... Data has been altered!`,
        discrepancyType: 'HASH_MISMATCH',
        educationalExplanation: explanation,
      };
    }

    expectedPrevHash = entry.current_entry_hash;
  }

  return {
    isValid: true,
    totalEntries: rows.length,
    genesisHash: GENESIS_HASH,
    tipHash: rows[rows.length - 1].current_entry_hash,
    verifiedCount: rows.length,
    educationalExplanation: explanation,
  };
}
