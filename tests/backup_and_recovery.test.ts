import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createBackup, restoreBackup } from '../server/backup.ts';
import { db, initDatabase } from '../server/db.ts';
import { removeEvidenceFile } from '../server/storage.ts';

test('Database backup creates atomic snapshot with valid SHA-256', async () => {
  initDatabase();

  const backup = await createBackup();
  assert.ok(fs.existsSync(backup.backupFile));
  assert.ok(backup.sha256.length === 64);
  assert.ok(backup.sizeBytes > 0);

  // Restore test
  const restoreResult = await restoreBackup(backup.backupFile);
  assert.equal(restoreResult.success, true);
});

test('removeEvidenceFile cleans up both storage and backup paths', async () => {
  const dummyFilename = `test-rollback-${Date.now()}.raw`;
  const storagePath = `./vault_storage/evidence/${dummyFilename}`;
  const backupPath = `./vault_storage/backups/${dummyFilename}`;

  // Create temporary files
  await fs.promises.writeFile(storagePath, 'temporary payload');
  await fs.promises.writeFile(backupPath, 'temporary payload');

  assert.equal(fs.existsSync(storagePath), true);
  assert.equal(fs.existsSync(backupPath), true);

  // Invoke cleanup
  await removeEvidenceFile(dummyFilename);

  // Must be removed from disk
  assert.equal(fs.existsSync(storagePath), false);
  assert.equal(fs.existsSync(backupPath), false);
});
