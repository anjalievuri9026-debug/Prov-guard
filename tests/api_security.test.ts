import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveSafePath, saveEvidenceFile } from '../server/storage.ts';
import { sha256 } from '../server/crypto.ts';
import { isValidCaseId, isValidUsername, recordFailedLogin, loginRateLimiter } from '../server/middleware/security.ts';
import { Request, Response } from 'express';

test('Path traversal attempts are rejected by resolveSafePath', () => {
  // Attempting to escape vault directory with ../ or absolute paths
  assert.throws(
    () => {
      resolveSafePath('../../../etc/passwd');
    },
    /Path traversal attempt detected|Access denied/
  );

  assert.throws(
    () => {
      resolveSafePath('..\\..\\windows\\system32\\cmd.exe');
    },
    /Path traversal attempt detected|Access denied/
  );
});

test('Zero-byte empty evidence file calculates standard NIST empty SHA-256', async () => {
  const emptyBuffer = Buffer.alloc(0);
  const emptyHash = sha256(emptyBuffer);
  assert.equal(emptyHash, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');

  const storageFilename = `empty-test-${Date.now()}.bin`;
  const result = await saveEvidenceFile(emptyBuffer, storageFilename);

  assert.equal(result.fileSizeBytes, 0);
  assert.equal(result.calculatedSha256, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('Input validators strictly enforce safe characters and formats', () => {
  // Case ID validation
  assert.equal(isValidCaseId('CASE-2026-ALPHA'), true);
  assert.equal(isValidCaseId('C-1'), true);
  assert.equal(isValidCaseId('CASE_99.1'), true);
  assert.equal(isValidCaseId('<script>alert(1)</script>'), false);
  assert.equal(isValidCaseId('CASE/../../ROOT'), false);
  assert.equal(isValidCaseId(''), false);

  // Username validation
  assert.equal(isValidUsername('admin'), true);
  assert.equal(isValidUsername('investigator_01'), true);
  assert.equal(isValidUsername('a'), false); // too short (< 3)
  assert.equal(isValidUsername('user; DROP TABLE users;--'), false);
});
