import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { sha256File } from './crypto.js';

const VAULT_ROOT = path.resolve(process.cwd(), 'vault_storage');
const EVIDENCE_DIR = path.join(VAULT_ROOT, 'evidence');
const BACKUP_DIR = path.join(VAULT_ROOT, 'backups');

if (!fs.existsSync(EVIDENCE_DIR)) {
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
}
if (!fs.existsSync(BACKUP_DIR)) {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
}

/**
 * Sanitizes and generates a cryptographically random, collision-resistant storage filename.
 */
export function generateStorageFilename(originalFilename: string): string {
  const ext = path.extname(originalFilename).slice(0, 10).replace(/[^a-zA-Z0-9.]/g, '');
  const randomId = crypto.randomUUID();
  return `${randomId}${ext || '.bin'}`;
}

/**
 * Resolves and validates that a storage filename cannot escape the private vault directory.
 */
export function resolveSafePath(storageFilename: string): string {
  if (storageFilename.includes('..') || storageFilename.includes('/') || storageFilename.includes('\\')) {
    throw new Error('Path traversal attempt detected. Access denied.');
  }
  const baseName = path.basename(storageFilename);
  const resolved = path.resolve(EVIDENCE_DIR, baseName);
  if (!resolved.startsWith(EVIDENCE_DIR)) {
    throw new Error('Path traversal attempt detected. Access denied.');
  }
  return resolved;
}

/**
 * Saves uploaded file buffer to private vault storage.
 * Automatically saves a pristine backup copy for educational tamper-testing and restoration.
 */
export async function saveEvidenceFile(buffer: Buffer, storageFilename: string): Promise<{
  filePath: string;
  fileSizeBytes: number;
  calculatedSha256: string;
}> {
  const targetPath = resolveSafePath(storageFilename);
  const backupPath = path.resolve(BACKUP_DIR, path.basename(storageFilename));

  // Write file to private storage
  await fs.promises.writeFile(targetPath, buffer);
  // Keep pristine backup copy specifically to allow one-click recovery after educational tampering demonstrations
  await fs.promises.writeFile(backupPath, buffer);

  const stats = await fs.promises.stat(targetPath);
  const calculatedSha256 = await sha256File(targetPath);

  return {
    filePath: targetPath,
    fileSizeBytes: stats.size,
    calculatedSha256,
  };
}

/**
 * Verifies live evidence integrity by calculating SHA-256 directly from the stored file bytes on disk.
 */
export async function verifyEvidenceIntegrity(storageFilename: string, originalSha256: string): Promise<{
  status: 'VERIFIED' | 'TAMPER_DETECTED' | 'MISSING_FILE' | 'VERIFICATION_FAILED';
  calculatedSha256: string | null;
  fileSizeBytes: number | null;
  matched: boolean;
  message: string;
}> {
  try {
    const targetPath = resolveSafePath(storageFilename);

    if (!fs.existsSync(targetPath)) {
      return {
        status: 'MISSING_FILE',
        calculatedSha256: null,
        fileSizeBytes: null,
        matched: false,
        message: 'Evidence file is physically missing from disk storage.',
      };
    }

    const stats = await fs.promises.stat(targetPath);
    const currentSha256 = await sha256File(targetPath);

    if (currentSha256.toLowerCase() === originalSha256.toLowerCase()) {
      return {
        status: 'VERIFIED',
        calculatedSha256: currentSha256,
        fileSizeBytes: stats.size,
        matched: true,
        message: 'Cryptographic integrity verified. Disk bytes match recorded SHA-256 digest exactly.',
      };
    } else {
      return {
        status: 'TAMPER_DETECTED',
        calculatedSha256: currentSha256,
        fileSizeBytes: stats.size,
        matched: false,
        message: 'CRITICAL INTEGRITY FAILURE: Live disk SHA-256 does not match original ingestion digest! File has been altered.',
      };
    }
  } catch (ioErr) {
    return {
      status: 'VERIFICATION_FAILED',
      calculatedSha256: null,
      fileSizeBytes: null,
      matched: false,
      message: 'Storage I/O failure: unable to read evidence bytes from vault disk: ' + (ioErr instanceof Error ? ioErr.message : String(ioErr)),
    };
  }
}

/**
 * Educational Simulation Utility:
 * Injects a 1-byte alteration into the stored file to demonstrate forensic integrity failure.
 */
export async function injectTampering(storageFilename: string): Promise<{ success: boolean; byteAltered: number }> {
  const targetPath = resolveSafePath(storageFilename);
  if (!fs.existsSync(targetPath)) {
    throw new Error('Cannot tamper with non-existent file');
  }

  const data = await fs.promises.readFile(targetPath);
  if (data.length === 0) {
    const altered = Buffer.from([0x01]);
    await fs.promises.writeFile(targetPath, altered);
    return { success: true, byteAltered: 0 };
  }

  // Flip the bits of the very first byte
  data[0] = data[0] ^ 0xff;
  await fs.promises.writeFile(targetPath, data);

  return { success: true, byteAltered: 0 };
}

/**
 * Restores file from pristine backup after educational tampering demonstration.
 */
export async function restorePristineFile(storageFilename: string): Promise<boolean> {
  const targetPath = resolveSafePath(storageFilename);
  const backupPath = path.resolve(BACKUP_DIR, path.basename(storageFilename));

  if (!fs.existsSync(backupPath)) {
    throw new Error('No pristine backup available for restoration');
  }

  const pristineData = await fs.promises.readFile(backupPath);
  await fs.promises.writeFile(targetPath, pristineData);
  return true;
}

/**
 * Safely removes stored files and backups upon transaction rollback or cancellation.
 */
export async function removeEvidenceFile(storageFilename: string): Promise<void> {
  try {
    const targetPath = resolveSafePath(storageFilename);
    const backupPath = path.resolve(BACKUP_DIR, path.basename(storageFilename));
    if (fs.existsSync(targetPath)) await fs.promises.unlink(targetPath);
    if (fs.existsSync(backupPath)) await fs.promises.unlink(backupPath);
  } catch (err) {
    console.error('Failed to cleanup file on rollback:', err);
  }
}

