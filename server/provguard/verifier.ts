import { sha256 } from '../crypto.js';
import { buildMerkleTree } from './merkle.js';
import { verifyAcquisitionManifest, type SignedAcquisitionManifest } from './manifest.js';
import { validateEvidenceGenealogy, type EvidenceArtifactNode } from './genealogy.js';

export type CheckStatus = 'PASS' | 'FAIL' | 'UNKNOWN' | 'SKIPPED';

export interface OfflineVerificationInput {
  evidenceBytes: Uint8Array;
  signedManifest: SignedAcquisitionManifest;
  /** Public keys must be provisioned independently from the evidence package. */
  trustedPublicKeys: Readonly<Record<string, string>>;
  expectedMerkleRoot?: string;
  genealogyNodes?: readonly EvidenceArtifactNode[];
}

export interface OfflineVerificationReport {
  schemaVersion: 'PROVGUARD_OFFLINE_REPORT_V1';
  assessment: 'COMPONENT_CHECKS_PASSED' | 'REVIEW_REQUIRED';
  checks: {
    byteIntegrity: CheckStatus;
    manifestSignature: CheckStatus;
    merkleRoot: CheckStatus;
    genealogy: CheckStatus;
    trustedTimestamp: 'NOT_CONFIGURED';
  };
  calculated: {
    sha256: string;
    fileSizeBytes: number;
    merkleRoot: string;
  };
  findings: string[];
  limitations: string[];
}

/**
 * Verify the cryptographic claims that can be checked offline.
 * This does not determine whether evidence is authentic, truthful, or admissible.
 */
export function verifyOfflineEvidence(input: OfflineVerificationInput): OfflineVerificationReport {
  const manifest = input.signedManifest.manifest;
  const actualSha256 = sha256(Buffer.from(input.evidenceBytes));
  const actualSize = input.evidenceBytes.byteLength;
  const tree = buildMerkleTree(input.evidenceBytes);
  const findings: string[] = [];
  const limitations: string[] = [
    'A successful hash or signature check does not prove that the source device, acquisition process, or underlying events were truthful.',
    'The manifest signing public key must be trusted independently; a public key supplied only inside this package is not a trust anchor.',
    'Trusted timestamp verification is not configured in this starter module. Local server timestamps are not treated as independent time proof.',
  ];

  const byteIntegrity: CheckStatus = actualSha256.toLowerCase() === manifest.file.sha256.toLowerCase() && actualSize === manifest.file.sizeBytes
    ? 'PASS'
    : 'FAIL';
  if (byteIntegrity === 'FAIL') findings.push('Evidence bytes do not match the size and SHA-256 recorded in the acquisition manifest.');

  const trustedKey = input.trustedPublicKeys[input.signedManifest.signature.keyId];
  const manifestSignature: CheckStatus = trustedKey
    ? (verifyAcquisitionManifest(input.signedManifest, trustedKey) ? 'PASS' : 'FAIL')
    : 'UNKNOWN';
  if (manifestSignature === 'FAIL') findings.push('The acquisition manifest signature is invalid.');
  if (manifestSignature === 'UNKNOWN') findings.push('No independently trusted public key is configured for the manifest signer.');

  let merkleRoot: CheckStatus = 'SKIPPED';
  if (input.expectedMerkleRoot) {
    merkleRoot = tree.rootHash.toLowerCase() === input.expectedMerkleRoot.toLowerCase() ? 'PASS' : 'FAIL';
    if (merkleRoot === 'FAIL') findings.push('The calculated Merkle root does not match the expected root.');
  }

  let genealogy: CheckStatus = 'SKIPPED';
  if (input.genealogyNodes) {
    const result = validateEvidenceGenealogy(input.genealogyNodes);
    genealogy = result.isStructurallyValid ? 'PASS' : 'FAIL';
    for (const finding of result.findings) findings.push(`${finding.code}: ${finding.message}`);
  }

  const requiredChecks: CheckStatus[] = [byteIntegrity, manifestSignature];
  const assessment = requiredChecks.every((status) => status === 'PASS') &&
    (merkleRoot === 'PASS' || merkleRoot === 'SKIPPED') &&
    (genealogy === 'PASS' || genealogy === 'SKIPPED')
    ? 'COMPONENT_CHECKS_PASSED'
    : 'REVIEW_REQUIRED';

  return {
    schemaVersion: 'PROVGUARD_OFFLINE_REPORT_V1',
    assessment,
    checks: {
      byteIntegrity,
      manifestSignature,
      merkleRoot,
      genealogy,
      trustedTimestamp: 'NOT_CONFIGURED',
    },
    calculated: {
      sha256: actualSha256,
      fileSizeBytes: actualSize,
      merkleRoot: tree.rootHash,
    },
    findings,
    limitations,
  };
}
