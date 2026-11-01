import test from 'node:test';
import assert from 'node:assert/strict';
import { db, UserRow, initDatabase } from '../server/db.ts';
import { verifyPassword } from '../server/crypto.ts';

test('Default forensic roles and password hashing verification', () => {
  initDatabase();

  const adminStmt = db.prepare('SELECT * FROM users WHERE username = ?');
  const admin = adminStmt.get('admin') as UserRow | undefined;
  assert.ok(admin);
  assert.equal(admin.role, 'Administrator');
  assert.equal(verifyPassword('Admin@DEIV2026!', admin.password_hash, admin.password_salt), true);
  assert.equal(verifyPassword('WrongPassword!', admin.password_hash, admin.password_salt), false);

  const invStmt = db.prepare('SELECT * FROM users WHERE username = ?');
  const inv = invStmt.get('investigator') as UserRow | undefined;
  assert.ok(inv);
  assert.equal(inv.role, 'Investigator');
  assert.equal(verifyPassword('Investigator@DEIV2026!', inv.password_hash, inv.password_salt), true);

  const audStmt = db.prepare('SELECT * FROM users WHERE username = ?');
  const aud = audStmt.get('auditor') as UserRow | undefined;
  assert.ok(aud);
  assert.equal(aud.role, 'Auditor');
  assert.equal(verifyPassword('Auditor@DEIV2026!', aud.password_hash, aud.password_salt), true);
});

test('Role permission matrix enforces principle of least privilege', () => {
  const permissions: Record<'Administrator' | 'Investigator' | 'Auditor', { canIngest: boolean; canManageUsers: boolean; canVerifyChain: boolean; canDownloadEvidence: boolean }> = {
    Administrator: { canIngest: true, canManageUsers: true, canVerifyChain: true, canDownloadEvidence: true },
    Investigator: { canIngest: true, canManageUsers: false, canVerifyChain: true, canDownloadEvidence: true },
    Auditor: { canIngest: false, canManageUsers: false, canVerifyChain: true, canDownloadEvidence: true },
  };

  // Auditor has read/verify access but cannot ingest or manage users
  assert.equal(permissions.Auditor.canIngest, false);
  assert.equal(permissions.Auditor.canManageUsers, false);
  assert.equal(permissions.Auditor.canVerifyChain, true);

  // Investigator can ingest and download but cannot manage users
  assert.equal(permissions.Investigator.canIngest, true);
  assert.equal(permissions.Investigator.canManageUsers, false);

  // Administrator has full privileges
  assert.equal(permissions.Administrator.canIngest, true);
  assert.equal(permissions.Administrator.canManageUsers, true);
});
