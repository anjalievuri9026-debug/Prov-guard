import test from 'node:test';
import assert from 'node:assert/strict';
import { sha256, hashPassword, verifyPassword, canonicalize, calculateEntryHash, GENESIS_HASH } from '../server/crypto.ts';

test('SHA-256 matches NIST standard test vectors', () => {
  // NIST vector: empty string
  const emptyHash = sha256('');
  assert.equal(emptyHash, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');

  // NIST vector: 'abc'
  const abcHash = sha256('abc');
  assert.equal(abcHash, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

  // NIST vector: 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
  const longHash = sha256('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq');
  assert.equal(longHash, '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
});

test('Password hashing produces distinct salts and validates correctly', () => {
  const pwd = 'InvestigatorPassword123!';
  const auth1 = hashPassword(pwd);
  const auth2 = hashPassword(pwd);

  // Salts must differ even for identical input passwords
  assert.notEqual(auth1.salt, auth2.salt);
  assert.notEqual(auth1.hash, auth2.hash);

  // Correct password verification
  assert.equal(verifyPassword(pwd, auth1.hash, auth1.salt), true);
  assert.equal(verifyPassword(pwd, auth2.hash, auth2.salt), true);

  // Incorrect password rejection
  assert.equal(verifyPassword('WrongPassword!', auth1.hash, auth1.salt), false);
  assert.equal(verifyPassword('', auth1.hash, auth1.salt), false);
});

test('Canonicalization produces deterministic order regardless of property insertion order', () => {
  const objA = { z: 1, a: 'test', m: { b: 2, a: 1 } };
  const objB = { a: 'test', m: { a: 1, b: 2 }, z: 1 };

  const canonA = canonicalize(objA);
  const canonB = canonicalize(objB);

  assert.equal(canonA, canonB);
  assert.equal(sha256(canonA), sha256(canonB));
});

test('Audit entry hash links to previous hash deterministically', () => {
  const prevHash = GENESIS_HASH;
  const hash1 = calculateEntryHash(prevHash, 'EVT-1', 'INGESTION', 'USR-1', '2026-10-29T10:00:00Z', { caseId: 'CASE-01' });
  const hash2 = calculateEntryHash(prevHash, 'EVT-1', 'INGESTION', 'USR-1', '2026-10-29T10:00:00Z', { caseId: 'CASE-01' });

  assert.equal(hash1, hash2);

  // Any variation in payload changes the entry hash completely
  const hashModified = calculateEntryHash(prevHash, 'EVT-1', 'INGESTION', 'USR-1', '2026-10-29T10:00:00Z', { caseId: 'CASE-02' });
  assert.notEqual(hash1, hashModified);
});
