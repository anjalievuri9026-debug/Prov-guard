import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { buildMerkleTree, createMerkleProof, verifyMerkleProof } from '../server/provguard/merkle.js';
import { signAcquisitionManifest, verifyAcquisitionManifest, type AcquisitionManifest } from '../server/provguard/manifest.js';
import { validateEvidenceGenealogy, type EvidenceArtifactNode } from '../server/provguard/genealogy.js';
import { assessChronology } from '../server/provguard/consistency.js';
import { signAuditCheckpoint, verifyAuditCheckpoint } from '../server/provguard/checkpoint.js';
import { verifyOfflineEvidence } from '../server/provguard/verifier.js';
import { sha256 } from '../server/crypto.js';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

function sampleManifest(bytes: Buffer): AcquisitionManifest {
  return {
    schemaVersion: 'PROVGUARD_ACQUISITION_V1',
    evidenceId: 'EVD-TEST-001',
    caseId: 'CASE-TEST-001',
    file: {
      originalFilename: 'sample.txt',
      mimeType: 'text/plain',
      sizeBytes: bytes.length,
      sha256: sha256(bytes),
    },
    acquisition: {
      acquiredAtUtc: '2026-10-30T10:00:00.000Z',
      recordedAtUtc: '2026-10-30T10:01:00.000Z',
      timezone: 'UTC',
      sourceType: 'test fixture',
      sourceDescription: 'Synthetic test evidence',
      collectionMethod: 'test fixture creation',
      toolName: 'PROV-GUARD test runner',
      toolVersion: '1.0.0',
      operatorId: 'test-operator',
      clockUncertaintyMs: 1000,
    },
  };
}

test('Merkle root and inclusion proof verify a chunk', () => {
  const bytes = Buffer.from('abcdefghij');
  const tree = buildMerkleTree(bytes, 4);
  const { chunk, proof, rootHash } = createMerkleProof(bytes, 1, 4);
  assert.equal(tree.rootHash, rootHash);
  assert.equal(chunk.toString(), 'efgh');
  assert.equal(verifyMerkleProof(chunk, proof, tree.rootHash), true);
  assert.equal(verifyMerkleProof(Buffer.from('evil'), proof, tree.rootHash), false);
});

test('Merkle tree handles an empty file deterministically', () => {
  const tree = buildMerkleTree(Buffer.alloc(0), 8);
  const { chunk, proof } = createMerkleProof(Buffer.alloc(0), 0, 8);
  assert.equal(tree.leafCount, 1);
  assert.equal(verifyMerkleProof(chunk, proof, tree.rootHash), true);
});

test('Acquisition manifest signature verifies and detects manifest changes', () => {
  const bytes = Buffer.from('synthetic forensic evidence');
  const signed = signAcquisitionManifest(sampleManifest(bytes), privateKeyPem, 'test-key-01');
  assert.equal(verifyAcquisitionManifest(signed, publicKeyPem), true);
  const changed = { ...signed, manifest: { ...signed.manifest, caseId: 'CASE-CHANGED' } };
  assert.equal(verifyAcquisitionManifest(changed, publicKeyPem), false);
});

test('Genealogy accepts a valid parent-child graph and rejects a cycle', () => {
  const nodes: EvidenceArtifactNode[] = [
    { artifactId: 'original', sha256: 'a'.repeat(64), parentArtifactIds: [], createdAtUtc: '2026-10-30T10:00:00.000Z' },
    { artifactId: 'derived', sha256: 'b'.repeat(64), parentArtifactIds: ['original'], createdAtUtc: '2026-10-30T10:05:00.000Z' },
  ];
  assert.equal(validateEvidenceGenealogy(nodes).isStructurallyValid, true);
  const cyclic = [
    { ...nodes[0], parentArtifactIds: ['derived'] },
    { ...nodes[1], parentArtifactIds: ['original'] },
  ];
  assert.equal(validateEvidenceGenealogy(cyclic).findings.some((item) => item.code === 'CYCLE_DETECTED'), true);
});

test('Chronology evaluator distinguishes conflict from uncertainty', () => {
  const observations = [
    { id: 'acquired', label: 'Acquisition', timestampUtc: '2026-10-30T10:00:00.000Z', source: 'operator' as const, uncertaintyMs: 0 },
    { id: 'received', label: 'Server receipt', timestampUtc: '2026-10-30T09:00:00.000Z', source: 'server' as const, uncertaintyMs: 0 },
  ];
  const [finding] = assessChronology(observations, [{ beforeId: 'acquired', afterId: 'received', explanation: 'Acquisition should precede server receipt.' }]);
  assert.equal(finding.status, 'CONFLICT');
});

test('Signed audit checkpoint verifies with trusted key', () => {
  const checkpoint = signAuditCheckpoint({
    schemaVersion: 'PROVGUARD_AUDIT_CHECKPOINT_V1',
    checkpointId: 'CHK-001',
    auditSequence: 12,
    auditHeadHash: 'c'.repeat(64),
    createdAtUtc: '2026-10-30T10:10:00.000Z',
    signerKeyId: 'test-key-01',
  }, privateKeyPem);
  assert.equal(verifyAuditCheckpoint(checkpoint, publicKeyPem), true);
});

test('Offline verifier reports byte, signature and Merkle checks separately', () => {
  const bytes = Buffer.from('synthetic evidence for offline verification');
  const signedManifest = signAcquisitionManifest(sampleManifest(bytes), privateKeyPem, 'test-key-01');
  const expectedMerkleRoot = buildMerkleTree(bytes).rootHash;
  const report = verifyOfflineEvidence({
    evidenceBytes: bytes,
    signedManifest,
    trustedPublicKeys: { 'test-key-01': publicKeyPem },
    expectedMerkleRoot,
  });
  assert.equal(report.assessment, 'COMPONENT_CHECKS_PASSED');
  assert.equal(report.checks.byteIntegrity, 'PASS');
  assert.equal(report.checks.manifestSignature, 'PASS');
  assert.equal(report.checks.merkleRoot, 'PASS');
  assert.equal(report.checks.trustedTimestamp, 'NOT_CONFIGURED');
});
