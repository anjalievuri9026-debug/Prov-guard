import { generateKeyPairSync, createPrivateKey, createPublicKey } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/**
 * PROV-GUARD Safe Key Management.
 *
 * Security Requirements:
 * - Ed25519 digital signatures.
 * - Private keys are NEVER stored in plaintext in the SQLite database or committed to git.
 * - In production, the private key is loaded from PROVGUARD_SIGNING_KEY_PEM environment variable.
 * - In development, an in-memory or secure local key file (data/.provguard-server-key.pem) is persisted
 *   so restarts and tests reuse the identical key pair.
 * - Public keys are published to the trusted_signing_keys table with key IDs for verification.
 */

export const DEFAULT_SERVER_KEY_ID = 'KEY-PROVGUARD-SERVER-01';

interface ServerKeyBundle {
  keyId: string;
  privateKeyPem: string;
  publicKeyPem: string;
}

let activeKeyBundle: ServerKeyBundle | null = null;

const DATA_DIR = path.resolve(process.cwd(), 'data');
const LOCAL_KEY_FILE = path.join(DATA_DIR, '.provguard-server-key.pem');

export function getServerSigningKey(): ServerKeyBundle {
  if (activeKeyBundle) {
    return activeKeyBundle;
  }

  const envKeyPem = process.env.PROVGUARD_SIGNING_KEY_PEM;
  if (envKeyPem) {
    try {
      const privateKey = createPrivateKey(envKeyPem);
      const publicKey = createPublicKey(privateKey);
      const keyId = process.env.PROVGUARD_SIGNING_KEY_ID || DEFAULT_SERVER_KEY_ID;
      activeKeyBundle = {
        keyId,
        privateKeyPem: envKeyPem,
        publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      };
      return activeKeyBundle;
    } catch (err) {
      console.warn('[PROVGUARD] Invalid PROVGUARD_SIGNING_KEY_PEM in env, falling back to local key.', err);
    }
  }

  // Check if local dev key exists in data/.provguard-server-key.pem
  if (fs.existsSync(LOCAL_KEY_FILE)) {
    try {
      const savedPem = fs.readFileSync(LOCAL_KEY_FILE, 'utf8');
      const privateKey = createPrivateKey(savedPem);
      const publicKey = createPublicKey(privateKey);
      activeKeyBundle = {
        keyId: DEFAULT_SERVER_KEY_ID,
        privateKeyPem: savedPem,
        publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      };
      return activeKeyBundle;
    } catch {
      // Re-generate if corrupt
    }
  }

  // Generate an Ed25519 keypair for local/development run
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();

  try {
    fs.writeFileSync(LOCAL_KEY_FILE, privateKeyPem, { mode: 0o600 });
  } catch {
    // Ephemeral fallback if filesystem is read-only
  }

  activeKeyBundle = {
    keyId: DEFAULT_SERVER_KEY_ID,
    privateKeyPem,
    publicKeyPem,
  };

  return activeKeyBundle;
}

export function getServerPublicKeyPem(): string {
  return getServerSigningKey().publicKeyPem;
}

export function getServerKeyId(): string {
  return getServerSigningKey().keyId;
}
