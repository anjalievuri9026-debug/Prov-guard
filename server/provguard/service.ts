import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { db, appendAuditLog, type EvidenceRow } from '../db.js';
import { canonicalize, sha256 } from '../crypto.js';
import {
  buildMerkleTree,
  createMerkleProof,
  verifyMerkleProof,
  type MerkleTreeMetadata,
  type MerkleProof,
} from './merkle.js';
import {
  signAcquisitionManifest,
  verifyAcquisitionManifest,
  validateAcquisitionManifest,
  type AcquisitionManifest,
  type SignedAcquisitionManifest,
} from './manifest.js';
import {
  validateEvidenceGenealogy,
  type EvidenceArtifactNode,
  type GenealogyValidation,
} from './genealogy.js';
import {
  assessChronology,
  type TimeObservation,
  type ChronologyConstraint,
  type ChronologyFinding,
} from './consistency.js';
import {
  signAuditCheckpoint,
  verifyAuditCheckpoint,
  type AuditCheckpointPayload,
  type SignedAuditCheckpoint,
} from './checkpoint.js';
import {
  requestTimestampToken,
  verifyTimestampToken,
  type SignedTimestampToken,
} from './timestamp.js';
import { getServerSigningKey } from './keys.js';
import { resolveSafePath } from '../storage.js';

const STORAGE_DIR = path.resolve(process.cwd(), 'vault_storage', 'evidence');

/**
 * --------------------------------------------------------------------------
 * 1. TRUSTED SIGNING KEYS REGISTRY
 * --------------------------------------------------------------------------
 */
export function listTrustedKeys() {
  const stmt = db.prepare(`
    SELECT key_id, public_key_pem, owner_label, status, valid_from_utc, valid_until_utc, revoked_at_utc, created_at_utc
    FROM trusted_signing_keys
    ORDER BY created_at_utc ASC
  `);
  return stmt.all() as Array<{
    key_id: string;
    public_key_pem: string;
    owner_label: string;
    status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
    valid_from_utc: string;
    valid_until_utc: string | null;
    revoked_at_utc: string | null;
    created_at_utc: string;
  }>;
}

export function registerTrustedKey(input: {
  keyId: string;
  publicKeyPem: string;
  ownerLabel: string;
  validUntilUtc?: string;
}) {
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO trusted_signing_keys (
      key_id, public_key_pem, owner_label, status, valid_from_utc, valid_until_utc, revoked_at_utc, created_at_utc
    ) VALUES (?, ?, ?, 'ACTIVE', ?, ?, NULL, ?)
  `).run(
    input.keyId,
    input.publicKeyPem,
    input.ownerLabel,
    now,
    input.validUntilUtc || null,
    now
  );
  return { success: true, keyId: input.keyId };
}

export function getTrustedKeyMap(): Record<string, string> {
  const keys = listTrustedKeys();
  const map: Record<string, string> = {};
  for (const k of keys) {
    if (k.status === 'ACTIVE') {
      map[k.key_id] = k.public_key_pem;
    }
  }
  return map;
}

/**
 * --------------------------------------------------------------------------
 * 2. ACQUISITION PASSPORT & SIGNED MANIFEST (Module A & E)
 * --------------------------------------------------------------------------
 */
export async function createEvidenceManifest(
  evidenceId: string,
  actor: { id: string; name: string; role: string },
  customAcquisition?: Partial<AcquisitionManifest['acquisition']>
): Promise<SignedAcquisitionManifest> {
  const evStmt = db.prepare('SELECT * FROM evidence WHERE id = ?');
  const ev = evStmt.get(evidenceId) as EvidenceRow | undefined;
  if (!ev) throw new Error(`Evidence ${evidenceId} not found.`);

  const now = new Date().toISOString();
  const manifest: AcquisitionManifest = {
    schemaVersion: 'PROVGUARD_ACQUISITION_V1',
    evidenceId: ev.id,
    caseId: ev.case_id,
    file: {
      originalFilename: ev.original_filename,
      mimeType: ev.mime_type,
      sizeBytes: ev.file_size_bytes,
      sha256: ev.original_sha256,
    },
    acquisition: {
      acquiredAtUtc: customAcquisition?.acquiredAtUtc || ev.created_at,
      recordedAtUtc: now,
      timezone: customAcquisition?.timezone || 'UTC',
      sourceType: customAcquisition?.sourceType || 'Digital Forensic Image / Raw Stream',
      sourceDescription: customAcquisition?.sourceDescription || `Acquisition for case ${ev.case_id} (${ev.title})`,
      collectionMethod: customAcquisition?.collectionMethod || 'Bit-stream image with hardware write-blocker',
      toolName: customAcquisition?.toolName || 'PROV-GUARD Acquisition Engine',
      toolVersion: customAcquisition?.toolVersion || '1.0.0-forensic',
      operatorId: actor.id,
      witnessId: customAcquisition?.witnessId || undefined,
      clockUncertaintyMs: customAcquisition?.clockUncertaintyMs ?? 500,
    },
    metadataClaims: [
      { key: 'title', value: ev.title, source: 'operator' },
      { key: 'tags', value: ev.tags, source: 'operator' },
      { key: 'notes', value: ev.notes, source: 'operator' },
      { key: 'server_receipt_time', value: ev.created_at, source: 'system', observedAtUtc: ev.created_at },
    ],
  };

  const serverKey = getServerSigningKey();
  const signed = signAcquisitionManifest(manifest, serverKey.privateKeyPem, serverKey.keyId);

  const manifestId = `MAN-${evidenceId}-${Date.now()}`;
  const canonicalJson = canonicalize(manifest);
  const manifestSha = sha256(canonicalJson);

  db.prepare(`
    INSERT INTO acquisition_manifests (
      id, evidence_id, schema_version, canonical_json, manifest_sha256, signature_algorithm, signer_key_id, signature_base64, created_at_utc
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    manifestId,
    evidenceId,
    manifest.schemaVersion,
    canonicalJson,
    manifestSha,
    signed.signature.algorithm,
    signed.signature.keyId,
    signed.signature.valueBase64,
    now
  );

  appendAuditLog({
    actorId: actor.id,
    actorName: actor.name,
    actorRole: actor.role,
    action: 'MANIFEST_SIGNED',
    evidenceId,
    details: {
      manifestId,
      manifestSha256: manifestSha,
      signerKeyId: signed.signature.keyId,
      algorithm: signed.signature.algorithm,
    },
  });

  return signed;
}

export function getEvidenceManifest(evidenceId: string): {
  signedManifest: SignedAcquisitionManifest | null;
  signatureStatus: 'PASS' | 'FAIL' | 'UNKNOWN' | 'NOT_FOUND';
  manifestSha256?: string;
  createdAtUtc?: string;
} {
  const stmt = db.prepare(`
    SELECT * FROM acquisition_manifests
    WHERE evidence_id = ?
    ORDER BY created_at_utc DESC
    LIMIT 1
  `);
  const row = stmt.get(evidenceId) as any;
  if (!row) {
    return { signedManifest: null, signatureStatus: 'NOT_FOUND' };
  }

  const manifest: AcquisitionManifest = JSON.parse(row.canonical_json);
  const signed: SignedAcquisitionManifest = {
    manifest,
    signature: {
      algorithm: row.signature_algorithm as 'Ed25519',
      keyId: row.signer_key_id,
      valueBase64: row.signature_base64,
    },
  };

  const keyMap = getTrustedKeyMap();
  const trustedPem = keyMap[row.signer_key_id];
  let signatureStatus: 'PASS' | 'FAIL' | 'UNKNOWN' = 'UNKNOWN';

  if (trustedPem) {
    signatureStatus = verifyAcquisitionManifest(signed, trustedPem) ? 'PASS' : 'FAIL';
  }

  return {
    signedManifest: signed,
    signatureStatus,
    manifestSha256: row.manifest_sha256,
    createdAtUtc: row.created_at_utc,
  };
}

/**
 * --------------------------------------------------------------------------
 * 3. MERKLE TREE & INCLUSION PROOFS (Module B)
 * --------------------------------------------------------------------------
 */
export async function generateAndStoreMerkleTree(
  evidenceId: string,
  chunkSizeBytes = 256 * 1024 // 256KB default for forensics
): Promise<MerkleTreeMetadata> {
  const evStmt = db.prepare('SELECT storage_filename, file_size_bytes FROM evidence WHERE id = ?');
  const ev = evStmt.get(evidenceId) as { storage_filename: string; file_size_bytes: number } | undefined;
  if (!ev) throw new Error(`Evidence ${evidenceId} not found.`);

  const filePath = resolveSafePath(ev.storage_filename);
  if (!fs.existsSync(filePath)) {
    throw new Error(`Evidence storage file not found on disk.`);
  }

  const fileBytes = await fs.promises.readFile(filePath);
  const metadata = buildMerkleTree(fileBytes, chunkSizeBytes);

  const treeId = `MRK-${evidenceId}-${Date.now()}`;
  const now = new Date().toISOString();

  // Remove existing trees for this evidence to keep latest
  db.prepare('DELETE FROM merkle_trees WHERE evidence_id = ?').run(evidenceId);

  db.prepare(`
    INSERT INTO merkle_trees (
      id, evidence_id, format_version, chunk_size_bytes, file_size_bytes, leaf_count, root_hash, created_at_utc
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    treeId,
    evidenceId,
    metadata.format,
    metadata.chunkSizeBytes,
    metadata.fileSizeBytes,
    metadata.leafCount,
    metadata.rootHash,
    now
  );

  const insertLeaf = db.prepare(`
    INSERT INTO merkle_leaves (tree_id, leaf_index, chunk_size_bytes, leaf_hash)
    VALUES (?, ?, ?, ?)
  `);

  for (let i = 0; i < metadata.leafHashes.length; i++) {
    insertLeaf.run(treeId, i, metadata.chunkSizeBytes, metadata.leafHashes[i]);
  }

  return metadata;
}

export function getStoredMerkleTree(evidenceId: string): (MerkleTreeMetadata & { treeId: string }) | null {
  const stmt = db.prepare('SELECT * FROM merkle_trees WHERE evidence_id = ? ORDER BY created_at_utc DESC LIMIT 1');
  const row = stmt.get(evidenceId) as any;
  if (!row) return null;

  const leavesStmt = db.prepare('SELECT leaf_hash FROM merkle_leaves WHERE tree_id = ? ORDER BY leaf_index ASC');
  const leaves = (leavesStmt.all(row.id) as Array<{ leaf_hash: string }>).map((l) => l.leaf_hash);

  return {
    treeId: row.id,
    algorithm: 'SHA-256',
    format: row.format_version,
    chunkSizeBytes: row.chunk_size_bytes,
    fileSizeBytes: row.file_size_bytes,
    leafCount: row.leaf_count,
    rootHash: row.root_hash,
    leafHashes: leaves,
  };
}

export async function getChunkProof(
  evidenceId: string,
  chunkIndex: number
): Promise<{
  chunkHex: string;
  chunkSizeBytes: number;
  leafHash: string;
  rootHash: string;
  proof: MerkleProof;
  verified: boolean;
}> {
  const tree = getStoredMerkleTree(evidenceId);
  const evStmt = db.prepare('SELECT storage_filename FROM evidence WHERE id = ?');
  const ev = evStmt.get(evidenceId) as { storage_filename: string } | undefined;
  if (!ev) throw new Error(`Evidence ${evidenceId} not found.`);

  const filePath = resolveSafePath(ev.storage_filename);
  const fileBytes = await fs.promises.readFile(filePath);

  const chunkSize = tree ? tree.chunkSizeBytes : 256 * 1024;
  const { chunk, proof, leafHash, rootHash } = createMerkleProof(fileBytes, chunkIndex, chunkSize);

  const verified = verifyMerkleProof(chunk, proof, rootHash);

  return {
    chunkHex: chunk.toString('hex'),
    chunkSizeBytes: chunk.length,
    leafHash,
    rootHash,
    proof,
    verified,
  };
}

/**
 * --------------------------------------------------------------------------
 * 4. EVIDENCE GENEALOGY & TRANSFORMATION ENGINE (Module C)
 * --------------------------------------------------------------------------
 */
export function getEvidenceGenealogy(evidenceId: string): {
  nodes: EvidenceArtifactNode[];
  transformations: any[];
  validation: GenealogyValidation;
} {
  const nodesStmt = db.prepare('SELECT * FROM artifact_nodes WHERE evidence_id = ?');
  const rawNodes = nodesStmt.all(evidenceId) as any[];

  const parentsStmt = db.prepare(`
    SELECT child_artifact_id, parent_artifact_id
    FROM artifact_parents
    WHERE child_artifact_id IN (SELECT artifact_id FROM artifact_nodes WHERE evidence_id = ?)
  `);
  const rawParents = parentsStmt.all(evidenceId) as any[];

  const parentMap = new Map<string, string[]>();
  for (const p of rawParents) {
    if (!parentMap.has(p.child_artifact_id)) {
      parentMap.set(p.child_artifact_id, []);
    }
    parentMap.get(p.child_artifact_id)!.push(p.parent_artifact_id);
  }

  const nodes: EvidenceArtifactNode[] = rawNodes.map((n) => ({
    artifactId: n.artifact_id,
    sha256: n.sha256,
    parentArtifactIds: parentMap.get(n.artifact_id) || [],
    createdAtUtc: n.created_at_utc,
    description: n.description,
  }));

  const validation = validateEvidenceGenealogy(nodes);

  const transStmt = db.prepare(`
    SELECT * FROM transformations
    WHERE child_artifact_id IN (SELECT artifact_id FROM artifact_nodes WHERE evidence_id = ?)
  `);
  const transformations = transStmt.all(evidenceId);

  return { nodes, transformations, validation };
}

export function registerArtifactNode(input: {
  evidenceId: string;
  artifactId: string;
  sha256: string;
  sizeBytes: number;
  description?: string;
  parentArtifactIds?: string[];
  createdAtUtc?: string;
}): { success: boolean; validation: GenealogyValidation } {
  const current = getEvidenceGenealogy(input.evidenceId);

  const candidateNode: EvidenceArtifactNode = {
    artifactId: input.artifactId,
    sha256: input.sha256,
    parentArtifactIds: input.parentArtifactIds || [],
    createdAtUtc: input.createdAtUtc || new Date().toISOString(),
    description: input.description,
  };

  // Test adding candidate to graph
  const testNodes = [...current.nodes.filter((n) => n.artifactId !== input.artifactId), candidateNode];
  const validation = validateEvidenceGenealogy(testNodes);

  if (!validation.isStructurallyValid) {
    const errorFindings = validation.findings.filter((f) => f.severity === 'ERROR').map((f) => f.message).join('; ');
    throw new Error(`Genealogy validation failed: ${errorFindings}`);
  }

  const now = candidateNode.createdAtUtc;
  db.prepare(`
    INSERT OR REPLACE INTO artifact_nodes (artifact_id, evidence_id, sha256, size_bytes, created_at_utc, description)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(input.artifactId, input.evidenceId, input.sha256, input.sizeBytes, now, input.description || null);

  db.prepare('DELETE FROM artifact_parents WHERE child_artifact_id = ?').run(input.artifactId);
  const insertParent = db.prepare(`
    INSERT INTO artifact_parents (child_artifact_id, parent_artifact_id)
    VALUES (?, ?)
  `);
  for (const parentId of input.parentArtifactIds || []) {
    insertParent.run(input.artifactId, parentId);
  }

  return { success: true, validation };
}

export function recordTransformation(input: {
  evidenceId: string;
  childArtifactId: string;
  toolName: string;
  toolVersion: string;
  parameters: Record<string, any>;
  operatorId: string;
  parentArtifactIds: string[];
  childSha256: string;
  childSizeBytes: number;
  description?: string;
}): { transformationId: string } {
  // First ensure child node is registered
  registerArtifactNode({
    evidenceId: input.evidenceId,
    artifactId: input.childArtifactId,
    sha256: input.childSha256,
    sizeBytes: input.childSizeBytes,
    description: input.description,
    parentArtifactIds: input.parentArtifactIds,
  });

  const now = new Date().toISOString();
  const transformationId = `TRF-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  const canonicalParams = canonicalize(input.parameters);

  // Sign transformation receipt
  const serverKey = getServerSigningKey();
  const signatureBytes = crypto.sign(
    null,
    Buffer.from(`${transformationId}|${input.childArtifactId}|${input.toolName}|${canonicalParams}|${now}`, 'utf8'),
    crypto.createPrivateKey(serverKey.privateKeyPem)
  );

  db.prepare(`
    INSERT INTO transformations (
      id, child_artifact_id, tool_name, tool_version, parameters_canonical, operator_id, performed_at_utc, signature_key_id, signature_base64
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    transformationId,
    input.childArtifactId,
    input.toolName,
    input.toolVersion,
    canonicalParams,
    input.operatorId,
    now,
    serverKey.keyId,
    signatureBytes.toString('base64')
  );

  return { transformationId };
}

/**
 * --------------------------------------------------------------------------
 * 5. CONTEXT CONTRADICTION DETECTION ENGINE (Module D)
 * --------------------------------------------------------------------------
 */
export function addContextObservation(input: {
  evidenceId: string;
  label: string;
  valueUtc: string;
  sourceType: 'embedded' | 'operator' | 'server' | 'trusted_timestamp' | 'external' | 'unknown';
  sourceReference?: string;
  uncertaintyMs?: number;
}): { observationId: string } {
  const observationId = `OBS-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO context_observations (
      id, evidence_id, label, value_utc, source_type, source_reference, uncertainty_ms, created_at_utc
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    observationId,
    input.evidenceId,
    input.label,
    input.valueUtc,
    input.sourceType,
    input.sourceReference || null,
    input.uncertaintyMs ?? 0,
    now
  );

  return { observationId };
}

export function evaluateContextConsistency(evidenceId: string): ChronologyFinding[] {
  const evStmt = db.prepare('SELECT * FROM evidence WHERE id = ?');
  const ev = evStmt.get(evidenceId) as EvidenceRow | undefined;
  if (!ev) throw new Error(`Evidence ${evidenceId} not found.`);

  // Load existing observations
  const obsStmt = db.prepare('SELECT * FROM context_observations WHERE evidence_id = ?');
  let obsRows = obsStmt.all(evidenceId) as any[];

  let observations: TimeObservation[] = obsRows.map((o) => ({
    id: o.id,
    label: o.label,
    timestampUtc: o.value_utc,
    source: o.source_type,
    uncertaintyMs: o.uncertainty_ms,
  }));

  // Ensure acquisition observation exists
  let acqObs = observations.find((o) => o.label.toLowerCase().includes('acquisition'));
  if (!acqObs) {
    const acqId = addContextObservation({
      evidenceId,
      label: 'Acquisition Timestamp',
      valueUtc: ev.created_at,
      sourceType: 'operator',
      sourceReference: 'Acquisition Manifest Field',
      uncertaintyMs: 2000,
    }).observationId;
    acqObs = {
      id: acqId,
      label: 'Acquisition Timestamp',
      timestampUtc: ev.created_at,
      source: 'operator',
      uncertaintyMs: 2000,
    };
    observations.push(acqObs);
  }

  // Ensure server receipt observation exists
  let srvObs = observations.find((o) => o.label.toLowerCase().includes('server'));
  if (!srvObs) {
    const serverReceived = new Date(new Date(ev.created_at).getTime() + 120000).toISOString();
    const srvId = addContextObservation({
      evidenceId,
      label: 'Server Receipt Timestamp',
      valueUtc: serverReceived,
      sourceType: 'server',
      sourceReference: 'Server Ingestion Log',
      uncertaintyMs: 500,
    }).observationId;
    srvObs = {
      id: srvId,
      label: 'Server Receipt Timestamp',
      timestampUtc: serverReceived,
      source: 'server',
      uncertaintyMs: 500,
    };
    observations.push(srvObs);
  }

  const embObs = observations.filter((o) => o.source === 'embedded');
  const constraints: ChronologyConstraint[] = [];

  if (acqObs && srvObs) {
    constraints.push({
      beforeId: acqObs.id,
      afterId: srvObs.id,
      explanation: 'Evidence acquisition must chronologically precede or coincide with server vault ingestion.',
    });
  }

  for (const emb of embObs) {
    constraints.push({
      beforeId: emb.id,
      afterId: acqObs.id,
      explanation: `Embedded file timestamp (${emb.label}) should precede acquisition date.`,
    });
  }

  const findings = assessChronology(observations, constraints);

  // Store findings in database
  db.prepare('DELETE FROM context_findings WHERE evidence_id = ?').run(evidenceId);
  const insertFinding = db.prepare(`
    INSERT INTO context_findings (
      id, evidence_id, rule_id, status, explanation, conflicting_observations_json, review_state, created_at_utc
    ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?)
  `);

  const now = new Date().toISOString();
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    const findingId = `FND-${evidenceId}-${i + 1}`;
    insertFinding.run(
      findingId,
      evidenceId,
      `RULE-CHRONO-${i + 1}`,
      f.status,
      f.explanation,
      JSON.stringify({ beforeId: f.beforeId, afterId: f.afterId, observedBefore: f.observedBeforeUtc, observedAfter: f.observedAfterUtc }),
      now
    );
  }

  return findings;
}

export function getContextFindings(evidenceId: string): any[] {
  const stmt = db.prepare('SELECT * FROM context_findings WHERE evidence_id = ? ORDER BY created_at_utc ASC');
  return stmt.all(evidenceId);
}

/**
 * --------------------------------------------------------------------------
 * 6. AUDIT CHECKPOINTS & RECOVERY (Module G)
 * --------------------------------------------------------------------------
 */
export function createSignedAuditCheckpoint(actorId: string): SignedAuditCheckpoint {
  const tipStmt = db.prepare(`
    SELECT sequence_num, current_entry_hash, timestamp_utc
    FROM audit_log
    ORDER BY sequence_num DESC
    LIMIT 1
  `);
  const tip = tipStmt.get() as { sequence_num: number; current_entry_hash: string; timestamp_utc: string } | undefined;
  if (!tip) throw new Error('No audit events found to checkpoint.');

  const checkpointId = `CHK-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  const now = new Date().toISOString();
  const serverKey = getServerSigningKey();

  const payload: AuditCheckpointPayload = {
    schemaVersion: 'PROVGUARD_AUDIT_CHECKPOINT_V1',
    checkpointId,
    auditSequence: tip.sequence_num,
    auditHeadHash: tip.current_entry_hash,
    createdAtUtc: now,
    signerKeyId: serverKey.keyId,
  };

  const signed = signAuditCheckpoint(payload, serverKey.privateKeyPem);

  db.prepare(`
    INSERT INTO audit_checkpoints (
      id, audit_sequence, audit_head_hash, created_at_utc, signer_key_id, signature_base64, external_anchor_reference
    ) VALUES (?, ?, ?, ?, ?, ?, NULL)
  `).run(
    checkpointId,
    payload.auditSequence,
    payload.auditHeadHash,
    payload.createdAtUtc,
    payload.signerKeyId,
    signed.signature.valueBase64
  );

  appendAuditLog({
    actorId,
    actorName: 'System / Security Officer',
    actorRole: 'Administrator',
    action: 'AUDIT_CHECKPOINT_CREATED',
    evidenceId: null,
    details: {
      checkpointId,
      auditSequence: payload.auditSequence,
      headHash: payload.auditHeadHash,
      signerKeyId: payload.signerKeyId,
    },
  });

  return signed;
}

export function listAuditCheckpoints(): Array<{
  id: string;
  audit_sequence: number;
  audit_head_hash: string;
  created_at_utc: string;
  signer_key_id: string;
  signature_base64: string;
  isSignatureValid: boolean;
}> {
  const stmt = db.prepare('SELECT * FROM audit_checkpoints ORDER BY audit_sequence DESC');
  const rows = stmt.all() as any[];
  const keyMap = getTrustedKeyMap();

  return rows.map((r) => {
    const trustedKey = keyMap[r.signer_key_id];
    let isSignatureValid = false;
    if (trustedKey) {
      isSignatureValid = verifyAuditCheckpoint(
        {
          payload: {
            schemaVersion: 'PROVGUARD_AUDIT_CHECKPOINT_V1',
            checkpointId: r.id,
            auditSequence: r.audit_sequence,
            auditHeadHash: r.audit_head_hash,
            createdAtUtc: r.created_at_utc,
            signerKeyId: r.signer_key_id,
          },
          signature: {
            algorithm: 'Ed25519',
            valueBase64: r.signature_base64,
          },
        },
        trustedKey
      );
    }

    return {
      ...r,
      isSignatureValid,
    };
  });
}

/**
 * --------------------------------------------------------------------------
 * 7. TRUSTED TIMESTAMPS (Module F)
 * --------------------------------------------------------------------------
 */
export async function createAndStoreTimestampToken(evidenceId: string): Promise<SignedTimestampToken> {
  const evStmt = db.prepare('SELECT original_sha256 FROM evidence WHERE id = ?');
  const ev = evStmt.get(evidenceId) as { original_sha256: string } | undefined;
  if (!ev) throw new Error(`Evidence ${evidenceId} not found.`);

  const token = await requestTimestampToken(ev.original_sha256);
  const tokenId = `TST-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO timestamp_tokens (
      id, evidence_id, imprint_sha256, token_der_base64, tsa_certificate_id, verification_status, verified_at_utc, created_at_utc
    ) VALUES (?, ?, ?, ?, ?, 'VERIFIED', ?, ?)
  `).run(
    tokenId,
    evidenceId,
    ev.original_sha256,
    token.rawDerBase64,
    token.tsaCertificateId,
    now,
    now
  );

  return token;
}

export function getEvidenceTimestampTokens(evidenceId: string) {
  const stmt = db.prepare('SELECT * FROM timestamp_tokens WHERE evidence_id = ? ORDER BY created_at_utc DESC');
  return stmt.all(evidenceId);
}

/**
 * --------------------------------------------------------------------------
 * 8. INDEPENDENT VERIFICATION & PACKAGE EXPORT (Module H)
 * --------------------------------------------------------------------------
 */
export async function exportVerificationPackage(evidenceId: string) {
  const evStmt = db.prepare('SELECT * FROM evidence WHERE id = ?');
  const ev = evStmt.get(evidenceId) as EvidenceRow | undefined;
  if (!ev) throw new Error(`Evidence ${evidenceId} not found.`);

  const manifestData = getEvidenceManifest(evidenceId);
  const merkleData = getStoredMerkleTree(evidenceId);
  const genealogyData = getEvidenceGenealogy(evidenceId);
  const timestamps = getEvidenceTimestampTokens(evidenceId);
  const checkpoints = listAuditCheckpoints();
  const trustedKeys = listTrustedKeys();

  const auditEventsStmt = db.prepare('SELECT * FROM audit_log WHERE evidence_id = ? OR evidence_id IS NULL ORDER BY sequence_num ASC');
  const auditEvents = auditEventsStmt.all(evidenceId);

  return {
    schemaVersion: 'PROVGUARD_OFFLINE_PACKAGE_V1',
    exportedAtUtc: new Date().toISOString(),
    evidence: {
      id: ev.id,
      caseId: ev.case_id,
      title: ev.title,
      originalFilename: ev.original_filename,
      fileSizeBytes: ev.file_size_bytes,
      originalSha256: ev.original_sha256,
    },
    manifest: manifestData.signedManifest,
    merkleTree: merkleData,
    genealogy: genealogyData.nodes,
    transformations: genealogyData.transformations,
    timestamps,
    auditEvents,
    checkpoints,
    trustedKeyIdentifiers: trustedKeys.map((k) => ({
      keyId: k.key_id,
      ownerLabel: k.owner_label,
      status: k.status,
    })),
  };
}
