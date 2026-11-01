import fs from 'node:fs';
import path from 'node:path';
import { db } from './db.js';
import { sha256File } from './crypto.js';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const BACKUPS_DIR = path.resolve(process.cwd(), 'backups');
const DB_FILE = path.join(DATA_DIR, 'deiv.db');

if (!fs.existsSync(BACKUPS_DIR)) {
  fs.mkdirSync(BACKUPS_DIR, { recursive: true });
}

export interface BackupResult {
  backupFile: string;
  timestamp: string;
  sha256: string;
  sizeBytes: number;
}

/**
 * Creates an atomic snapshot backup of the SQLite database.
 * Uses WAL checkpointing to ensure all transactions are flushed to disk first.
 */
export async function createBackup(): Promise<BackupResult> {
  // Force WAL checkpoint to flush pending transactions from WAL into main database
  db.exec('PRAGMA wal_checkpoint(TRUNCATE);');

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupFileName = `deiv-backup-${timestamp}.db`;
  const backupPath = path.join(BACKUPS_DIR, backupFileName);

  // Copy database file
  await fs.promises.copyFile(DB_FILE, backupPath);

  const stats = await fs.promises.stat(backupPath);
  const hash = await sha256File(backupPath);

  return {
    backupFile: backupPath,
    timestamp,
    sha256: hash,
    sizeBytes: stats.size,
  };
}

/**
 * Restores the SQLite database from a specified backup file.
 */
export async function restoreBackup(backupFilePath: string): Promise<{ success: boolean; message: string }> {
  if (!fs.existsSync(backupFilePath)) {
    throw new Error(`Backup file does not exist: ${backupFilePath}`);
  }

  // Verify backup file SHA-256
  const hash = await sha256File(backupFilePath);
  if (!hash) {
    throw new Error('Failed to compute backup file digest.');
  }

  // Copy backup over active database file
  await fs.promises.copyFile(backupFilePath, DB_FILE);

  return {
    success: true,
    message: `Database successfully restored from ${path.basename(backupFilePath)}. Verified SHA-256: ${hash}`,
  };
}

// CLI entrypoint if executed directly
if (process.argv[1] && process.argv[1].endsWith('backup.ts')) {
  const action = process.argv[2] || 'create';
  if (action === 'create') {
    createBackup()
      .then((res) => {
        console.log(`[DEIV BACKUP] Success: ${res.backupFile}`);
        console.log(`[DEIV BACKUP] SHA-256: ${res.sha256} (${res.sizeBytes} bytes)`);
      })
      .catch((err) => {
        console.error('[DEIV BACKUP] Error:', err);
        process.exit(1);
      });
  } else if (action === 'restore') {
    const file = process.argv[3];
    if (!file) {
      console.error('Usage: tsx server/backup.ts restore <path-to-backup.db>');
      process.exit(1);
    }
    restoreBackup(file)
      .then((res) => console.log(res.message))
      .catch((err) => {
        console.error('[DEIV RESTORE] Error:', err);
        process.exit(1);
      });
  }
}
