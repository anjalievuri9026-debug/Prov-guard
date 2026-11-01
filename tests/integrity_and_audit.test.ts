import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { sha256 } from '../server/crypto.ts';
import { saveEvidenceFile, verifyEvidenceIntegrity, injectTampering, restorePristineFile } from '../server/storage.ts';
import { initDatabase, db, appendAuditLog, verifyAuditChain } from '../server/db.ts';

test('Evidence file storage and byte-level SHA-256 calculation', async () => {
  const content = Buffer.from('Forensic Disk Sector Capture Sample 2026', 'utf-8');
  const expectedHash = sha256(content);

  const storageFilename = `test-${Date.now()}.raw`;
  const result = await saveEvidenceFile(content, storageFilename);

  assert.equal(result.calculatedSha256, expectedHash);
  assert.equal(result.fileSizeBytes, content.length);

  // Live integrity verification on pristine file
  const verification = await verifyEvidenceIntegrity(storageFilename, expectedHash);
  assert.equal(verification.matched, true);
  assert.equal(verification.status, 'VERIFIED');
  assert.equal(verification.calculatedSha256, expectedHash);

  // Invert 1 byte to simulate unauthorized disk tampering
  await injectTampering(storageFilename);

  // Re-verify: must catch the alteration!
  const tamperedVerification = await verifyEvidenceIntegrity(storageFilename, expectedHash);
  assert.equal(tamperedVerification.matched, false);
  assert.equal(tamperedVerification.status, 'TAMPER_DETECTED');
  assert.notEqual(tamperedVerification.calculatedSha256, expectedHash);

  // Restore pristine file
  await restorePristineFile(storageFilename);
  const restoredVerification = await verifyEvidenceIntegrity(storageFilename, expectedHash);
  assert.equal(restoredVerification.matched, true);
  assert.equal(restoredVerification.status, 'VERIFIED');
});

test('Missing evidence file triggers MISSING_FILE status', async () => {
  const verification = await verifyEvidenceIntegrity('non_existent_file_99999.raw', 'abcdef');
  assert.equal(verification.matched, false);
  assert.equal(verification.status, 'MISSING_FILE');
});

test('Audit log chain verification catches record alteration', () => {
  initDatabase();

  // Baseline chain verification should pass
  const baseline = verifyAuditChain();
  assert.equal(baseline.isValid, true);
  assert.ok(baseline.totalEntries > 0);

  // Add a new legitimate audit log
  const newEntry = appendAuditLog({
    actorId: 'test-actor-01',
    actorName: 'Test Investigator',
    actorRole: 'Investigator',
    action: 'TEST_EVIDENCE_ACCESS',
    evidenceId: 'EVD-TEST-001',
    details: { justification: 'Standard audit test' },
  });

  const verifiedAfterAppend = verifyAuditChain();
  assert.equal(verifiedAfterAppend.isValid, true);

  // Simulate malicious unauthorized SQL update on the details of that record
  db.prepare('UPDATE audit_log SET details_canonical = ? WHERE event_id = ?')
    .run('{"altered":"unauthorized modification"}', newEntry.event_id);

  // Chain verification must immediately fail with HASH_MISMATCH!
  const failedCheck = verifyAuditChain();
  assert.equal(failedCheck.isValid, false);
  assert.equal(failedCheck.discrepancyType, 'HASH_MISMATCH');
  assert.equal(failedCheck.brokenEventId, newEntry.event_id);

  // Revert back
  const originalCanonical = newEntry.details_canonical;
  db.prepare('UPDATE audit_log SET details_canonical = ? WHERE event_id = ?')
    .run(originalCanonical, newEntry.event_id);

  const restoredCheck = verifyAuditChain();
  assert.equal(restoredCheck.isValid, true);
});

test('Storage error safely triggers VERIFICATION_FAILED without false success', async () => {
  // Pass an invalid path that triggers safe error handling
  const verification = await verifyEvidenceIntegrity('../../invalid/path', 'abcdef');
  assert.equal(verification.matched, false);
  assert.equal(verification.status, 'VERIFICATION_FAILED');
  assert.equal(verification.calculatedSha256, null);
});

