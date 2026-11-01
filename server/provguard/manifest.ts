import { createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { canonicalize } from '../crypto.js';

export interface AcquisitionManifest {
  schemaVersion: 'PROVGUARD_ACQUISITION_V1';
  evidenceId: string;
  caseId: string;
  file: {
    originalFilename: string;
    mimeType: string;
    sizeBytes: number;
    sha256: string;
  };
  acquisition: {
    acquiredAtUtc: string;
    recordedAtUtc: string;
    timezone: string;
    sourceType: string;
    sourceDescription: string;
    collectionMethod: string;
    toolName: string;
    toolVersion: string;
    operatorId: string;
    witnessId?: string;
    clockUncertaintyMs?: number;
  };
  metadataClaims?: Array<{
    key: string;
    value: string;
    source: 'embedded' | 'operator' | 'system' | 'external';
    observedAtUtc?: string;
  }>;
}

export interface SignedAcquisitionManifest {
  manifest: AcquisitionManifest;
  signature: {
    algorithm: 'Ed25519';
    keyId: string;
    valueBase64: string;
  };
}

function isIsoDate(value: string): boolean {
  return typeof value === 'string' && value.length > 0 && Number.isFinite(Date.parse(value));
}

export function validateAcquisitionManifest(manifest: AcquisitionManifest): string[] {
  const errors: string[] = [];
  if (manifest.schemaVersion !== 'PROVGUARD_ACQUISITION_V1') errors.push('Unsupported manifest schema version.');
  if (!manifest.evidenceId?.trim()) errors.push('evidenceId is required.');
  if (!manifest.caseId?.trim()) errors.push('caseId is required.');
  if (!manifest.file?.originalFilename?.trim()) errors.push('Original filename is required.');
  if (!manifest.file?.mimeType?.trim()) errors.push('MIME type is required.');
  if (!Number.isSafeInteger(manifest.file?.sizeBytes) || manifest.file.sizeBytes < 0) errors.push('File size must be a non-negative safe integer.');
  if (!/^[a-f0-9]{64}$/i.test(manifest.file?.sha256 ?? '')) errors.push('File SHA-256 must be 64 hexadecimal characters.');
  if (!isIsoDate(manifest.acquisition?.acquiredAtUtc ?? '')) errors.push('acquiredAtUtc must be a parseable date/time.');
  if (!isIsoDate(manifest.acquisition?.recordedAtUtc ?? '')) errors.push('recordedAtUtc must be a parseable date/time.');
  if (!manifest.acquisition?.timezone?.trim()) errors.push('Acquisition timezone or UTC designation is required.');
  if (!manifest.acquisition?.sourceType?.trim()) errors.push('Source type is required.');
  if (!manifest.acquisition?.collectionMethod?.trim()) errors.push('Collection method is required.');
  if (!manifest.acquisition?.toolName?.trim()) errors.push('Acquisition tool name is required.');
  if (!manifest.acquisition?.toolVersion?.trim()) errors.push('Acquisition tool version is required.');
  if (!manifest.acquisition?.operatorId?.trim()) errors.push('Operator ID is required.');
  if (manifest.acquisition?.clockUncertaintyMs !== undefined &&
      (!Number.isFinite(manifest.acquisition.clockUncertaintyMs) || manifest.acquisition.clockUncertaintyMs < 0)) {
    errors.push('clockUncertaintyMs must be a non-negative number.');
  }
  return errors;
}

/** Sign the canonical manifest bytes with an Ed25519 private key in PEM format. */
export function signAcquisitionManifest(
  manifest: AcquisitionManifest,
  privateKeyPem: string,
  keyId: string,
): SignedAcquisitionManifest {
  const errors = validateAcquisitionManifest(manifest);
  if (errors.length) throw new Error(`Invalid acquisition manifest: ${errors.join(' ')}`);
  if (!keyId.trim()) throw new Error('keyId is required.');

  const signature = cryptoSign(
    null,
    Buffer.from(canonicalize(manifest), 'utf8'),
    createPrivateKey(privateKeyPem),
  );
  return {
    manifest,
    signature: {
      algorithm: 'Ed25519',
      keyId,
      valueBase64: signature.toString('base64'),
    },
  };
}

/** The public key must be trusted out-of-band; a key bundled by the same server is not independent trust. */
export function verifyAcquisitionManifest(
  signed: SignedAcquisitionManifest,
  trustedPublicKeyPem: string,
): boolean {
  try {
    if (signed.signature.algorithm !== 'Ed25519') return false;
    if (validateAcquisitionManifest(signed.manifest).length > 0) return false;
    const signatureBytes = Buffer.from(signed.signature.valueBase64, 'base64');
    if (signatureBytes.length !== 64) return false;
    return cryptoVerify(
      null,
      Buffer.from(canonicalize(signed.manifest), 'utf8'),
      createPublicKey(trustedPublicKeyPem),
      signatureBytes,
    );
  } catch {
    return false;
  }
}
