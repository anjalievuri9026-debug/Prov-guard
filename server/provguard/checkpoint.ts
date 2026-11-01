import { createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { canonicalize } from '../crypto.js';

export interface AuditCheckpointPayload {
  schemaVersion: 'PROVGUARD_AUDIT_CHECKPOINT_V1';
  checkpointId: string;
  auditSequence: number;
  auditHeadHash: string;
  createdAtUtc: string;
  signerKeyId: string;
}

export interface SignedAuditCheckpoint {
  payload: AuditCheckpointPayload;
  signature: {
    algorithm: 'Ed25519';
    valueBase64: string;
  };
}

export function signAuditCheckpoint(
  payload: AuditCheckpointPayload,
  privateKeyPem: string,
): SignedAuditCheckpoint {
  if (payload.schemaVersion !== 'PROVGUARD_AUDIT_CHECKPOINT_V1') throw new Error('Unsupported checkpoint schema.');
  if (!payload.checkpointId.trim() || !payload.signerKeyId.trim()) throw new Error('Checkpoint ID and signer key ID are required.');
  if (!Number.isSafeInteger(payload.auditSequence) || payload.auditSequence < 0) throw new Error('Invalid audit sequence.');
  if (!/^[a-f0-9]{64}$/i.test(payload.auditHeadHash)) throw new Error('Audit head hash must be SHA-256.');
  if (!Number.isFinite(Date.parse(payload.createdAtUtc))) throw new Error('createdAtUtc must be a parseable date/time.');

  const signature = cryptoSign(null, Buffer.from(canonicalize(payload), 'utf8'), createPrivateKey(privateKeyPem));
  return { payload, signature: { algorithm: 'Ed25519', valueBase64: signature.toString('base64') } };
}

export function verifyAuditCheckpoint(checkpoint: SignedAuditCheckpoint, trustedPublicKeyPem: string): boolean {
  try {
    if (checkpoint.signature.algorithm !== 'Ed25519') return false;
    if (!/^[a-f0-9]{64}$/i.test(checkpoint.payload.auditHeadHash)) return false;
    const signature = Buffer.from(checkpoint.signature.valueBase64, 'base64');
    if (signature.length !== 64) return false;
    return cryptoVerify(
      null,
      Buffer.from(canonicalize(checkpoint.payload), 'utf8'),
      createPublicKey(trustedPublicKeyPem),
      signature,
    );
  } catch {
    return false;
  }
}
