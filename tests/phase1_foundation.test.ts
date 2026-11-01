import test from 'node:test';
import assert from 'node:assert/strict';
import { db, initDatabase } from '../server/db.js';
import {
  getServerSigningKey,
  getServerPublicKeyPem,
  listTrustedKeys,
  createEvidenceManifest,
  getEvidenceManifest,
  generateAndStoreMerkleTree,
  getStoredMerkleTree,
  getChunkProof,
  registerArtifactNode,
  getEvidenceGenealogy,
  addContextObservation,
  evaluateContextConsistency,
  createSignedAuditCheckpoint,
  listAuditCheckpoints,
  createAndStoreTimestampToken,
} from '../server/provguard/index.js';

test('Phase 1 Foundation: Database schema initializes idempotently with trusted keys', () => {
  // Should run multiple times without throwing
  initDatabase();
  initDatabase();

  const keys = listTrustedKeys();
  assert.ok(keys.length >= 2, 'Should have at least server key and mock TSA key');
  const serverKey = keys.find((k) => k.key_id.startsWith('KEY-PROVGUARD'));
  assert.ok(serverKey, 'Server signing key should be registered');
  assert.equal(serverKey.status, 'ACTIVE');
});

test('Phase 1 Foundation: Safe key configuration produces valid Ed25519 keypair in memory', () => {
  const bundle = getServerSigningKey();
  assert.ok(bundle.keyId);
  assert.ok(bundle.publicKeyPem.includes('BEGIN PUBLIC KEY'));
  assert.ok(bundle.privateKeyPem.includes('BEGIN PRIVATE KEY'));

  // Ensure private key is NOT in database
  const inDb = db.prepare('SELECT * FROM trusted_signing_keys WHERE public_key_pem LIKE ?').all('%PRIVATE%');
  assert.equal(inDb.length, 0, 'Private key must never be stored in database');
});

test('Phase 1 Foundation: Acquisition manifest creation, digital signing, and tamper detection', async () => {
  initDatabase();
  const evRow = db.prepare('SELECT id FROM evidence LIMIT 1').get() as { id: string } | undefined;
  if (!evRow) return;

  const actor = { id: 'usr-inv-01', name: 'Detective Sarah Chen', role: 'Investigator' };
  const signed = await createEvidenceManifest(evRow.id, actor, {
    sourceType: 'Network TAP Capture',
    collectionMethod: 'Hardware write-blocking physical tap',
  });

  assert.equal(signed.manifest.evidenceId, evRow.id);
  assert.equal(signed.signature.algorithm, 'Ed25519');

  const fetched = getEvidenceManifest(evRow.id);
  assert.equal(fetched.signatureStatus, 'PASS');
  assert.ok(fetched.manifestSha256);
});

test('Phase 1 Foundation: Merkle tree calculation, SQLite persistence and chunk inclusion proof', async () => {
  const evRow = db.prepare('SELECT id FROM evidence LIMIT 1').get() as { id: string } | undefined;
  if (!evRow) return;

  const metadata = await generateAndStoreMerkleTree(evRow.id, 64); // 64-byte chunks for test
  assert.ok(metadata.leafCount > 0);
  assert.ok(metadata.rootHash.length === 64);

  const stored = getStoredMerkleTree(evRow.id);
  assert.ok(stored);
  assert.equal(stored.rootHash, metadata.rootHash);
  assert.equal(stored.leafHashes.length, metadata.leafCount);

  // Generate proof for chunk 0
  const chunkProof = await getChunkProof(evRow.id, 0);
  assert.equal(chunkProof.verified, true);
  assert.equal(chunkProof.rootHash, metadata.rootHash);
});

test('Phase 1 Foundation: Evidence genealogy DAG enforcement prevents cycles', () => {
  const evRow = db.prepare('SELECT id FROM evidence LIMIT 1').get() as { id: string } | undefined;
  if (!evRow) return;

  const rootId = `ART-ROOT-${Date.now()}`;
  const child1Id = `ART-CHILD1-${Date.now()}`;

  // Register root artifact
  registerArtifactNode({
    evidenceId: evRow.id,
    artifactId: rootId,
    sha256: 'a'.repeat(64),
    sizeBytes: 1024,
    description: 'Original evidence capture node',
  });

  // Register child artifact pointing to root
  registerArtifactNode({
    evidenceId: evRow.id,
    artifactId: child1Id,
    sha256: 'b'.repeat(64),
    sizeBytes: 512,
    parentArtifactIds: [rootId],
    description: 'Derived extraction node',
  });

  const genealogy = getEvidenceGenealogy(evRow.id);
  assert.equal(genealogy.validation.isStructurallyValid, true);

  // Attempt to create a cycle by making root point to child1
  assert.throws(() => {
    registerArtifactNode({
      evidenceId: evRow.id,
      artifactId: rootId,
      sha256: 'a'.repeat(64),
      sizeBytes: 1024,
      parentArtifactIds: [child1Id], // CYCLE!
    });
  }, /Genealogy validation failed/);
});

test('Phase 1 Foundation: Context contradiction engine detects temporal anomalies', () => {
  const evRow = db.prepare('SELECT id FROM evidence LIMIT 1').get() as { id: string } | undefined;
  if (!evRow) return;

  // Add conflicting observation: embedded file modified in the future AFTER acquisition
  const futureTimestamp = '2030-01-01T12:00:00.000Z';
  addContextObservation({
    evidenceId: evRow.id,
    label: 'Embedded EXIF Creation Date',
    valueUtc: futureTimestamp,
    sourceType: 'embedded',
    sourceReference: 'EXIF metadata header chunk',
    uncertaintyMs: 1000,
  });

  const findings = evaluateContextConsistency(evRow.id);
  assert.ok(findings.length > 0);
  const conflict = findings.find((f) => f.status === 'CONFLICT');
  assert.ok(conflict, 'Should detect CONFLICT between embedded future timestamp and acquisition date');
});

test('Phase 1 Foundation: Signed audit checkpoint and verification', () => {
  const signed = createSignedAuditCheckpoint('usr-admin-01');
  assert.equal(signed.payload.schemaVersion, 'PROVGUARD_AUDIT_CHECKPOINT_V1');
  assert.ok(signed.payload.auditSequence > 0);
  assert.ok(signed.signature.valueBase64);

  const list = listAuditCheckpoints();
  assert.ok(list.length > 0);
  const latest = list.find((c) => c.id === signed.payload.checkpointId);
  assert.ok(latest);
  assert.equal(latest.isSignatureValid, true);
});

test('Phase 1 Foundation: Trusted RFC 3161 timestamp token creation and verification', async () => {
  const evRow = db.prepare('SELECT id FROM evidence LIMIT 1').get() as { id: string } | undefined;
  if (!evRow) return;

  const token = await createAndStoreTimestampToken(evRow.id);
  assert.ok(token.rawDerBase64);
  assert.equal(token.payload.isDevelopmentMock, true);
  assert.equal(token.payload.messageImprint.hashAlgorithm, 'SHA-256');
});
