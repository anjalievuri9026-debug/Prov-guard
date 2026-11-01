import crypto from 'node:crypto';
import fs from 'node:fs';

export const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

/**
 * Calculates SHA-256 digest from Buffer or string.
 */
export function sha256(data: Buffer | string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Calculates SHA-256 directly from file on disk via streaming to avoid holding giant files in memory.
 */
export function sha256File(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('error', (err) => reject(err));
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

/**
 * Scrypt-based password hashing for secure authentication.
 */
export function hashPassword(password: string): { hash: string; salt: string } {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64);
  return { hash: derivedKey.toString('hex'), salt };
}

/**
 * Constant-time password verification to prevent timing attacks.
 */
export function verifyPassword(password: string, storedHash: string, salt: string): boolean {
  try {
    const derivedKey = crypto.scryptSync(password, salt, 64);
    const keyBuffer = Buffer.from(derivedKey.toString('hex'), 'hex');
    const storedBuffer = Buffer.from(storedHash, 'hex');
    if (keyBuffer.length !== storedBuffer.length) return false;
    return crypto.timingSafeEqual(keyBuffer, storedBuffer);
  } catch {
    return false;
  }
}

/**
 * Produces a deterministic canonical string representation of an object.
 * Keys are sorted recursively, numbers and strings are normalized, and no arbitrary whitespace is added.
 */
export function canonicalize(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalize).join(',') + ']';
  }
  const keys = Object.keys(obj as Record<string, unknown>)
    .filter((key) => (obj as Record<string, unknown>)[key] !== undefined)
    .sort();
  const pairs = keys.map((key) => {
    const val = (obj as Record<string, unknown>)[key];
    return `${JSON.stringify(key)}:${canonicalize(val)}`;
  });
  return '{' + pairs.join(',') + '}';
}

/**
 * Calculates the cryptographic hash for an audit log entry.
 * Current Hash = SHA256(prev_hash + ":" + canonical_details)
 */
export function calculateEntryHash(
  prevHash: string,
  eventId: string,
  action: string,
  actorId: string,
  timestampUtc: string,
  details: unknown
): string {
  const canonicalDetails = canonicalize(details);
  const payload = `${prevHash}|${eventId}|${action}|${actorId}|${timestampUtc}|${canonicalDetails}`;
  return sha256(payload);
}
