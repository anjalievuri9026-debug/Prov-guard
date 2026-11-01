import { createHash, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify, createPrivateKey, createPublicKey } from 'node:crypto';
import { canonicalize } from '../crypto.js';

/**
 * PROV-GUARD RFC 3161 Trusted Timestamp Provider Interface.
 *
 * NOTE: Development mock provider is clearly marked as NON-PRODUCTION.
 * Local computer timestamps are never represented as independently trusted time.
 */

export interface TimestampTokenPayload {
  version: number;
  policyId: string;
  messageImprint: {
    hashAlgorithm: 'SHA-256';
    hashedMessageHex: string;
  };
  serialNumber: string;
  genTimeUtc: string;
  tsaName: string;
  accuracyMs?: number;
  nonce?: string;
  isDevelopmentMock: boolean;
}

export interface SignedTimestampToken {
  format: 'RFC3161_DER_BASE64_SIMULATED' | 'RFC3161_DER_BASE64';
  payload: TimestampTokenPayload;
  tsaCertificateId: string;
  tsaPublicKeyPem: string;
  signatureBase64: string;
  rawDerBase64: string;
}

export interface TimestampVerificationResult {
  isValid: boolean;
  status: 'VERIFIED' | 'INVALID' | 'IMPRINT_MISMATCH' | 'TSA_UNTRUSTED' | 'NOT_CONFIGURED';
  tsaName: string;
  genTimeUtc?: string;
  accuracyMs?: number;
  isDevelopmentMock: boolean;
  explanation: string;
}

// Development mock TSA authority keys (clearly marked non-production)
const mockTsaKeys = generateKeyPairSync('ed25519');
const mockTsaPrivateKeyPem = mockTsaKeys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
export const MOCK_TSA_PUBLIC_KEY_PEM = mockTsaKeys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
export const MOCK_TSA_CERT_ID = 'TSA-DEV-MOCK-RFC3161-CERT-01';
export const MOCK_TSA_NAME = 'Development Mock TSA (Non-Production Simulated Authority)';

/**
 * Requests an RFC 3161 timestamp token for a given SHA-256 hash digest.
 * In development, uses the non-production mock authority with explicit labeling.
 */
export async function requestTimestampToken(
  sha256DigestHex: string,
  options?: { nonce?: string }
): Promise<SignedTimestampToken> {
  if (!/^[a-f0-9]{64}$/i.test(sha256DigestHex)) {
    throw new Error('SHA-256 digest must be 64 hexadecimal characters.');
  }

  const now = new Date().toISOString();
  const serial = `SN-${Date.now()}-${Math.floor(Math.random() * 1000000)}`;

  const payload: TimestampTokenPayload = {
    version: 1,
    policyId: '1.3.6.1.4.1.99999.provguard.mock.tsa.policy.1',
    messageImprint: {
      hashAlgorithm: 'SHA-256',
      hashedMessageHex: sha256DigestHex.toLowerCase(),
    },
    serialNumber: serial,
    genTimeUtc: now,
    tsaName: MOCK_TSA_NAME,
    accuracyMs: 50,
    nonce: options?.nonce || Math.random().toString(36).substring(2),
    isDevelopmentMock: true,
  };

  const canonicalPayload = canonicalize(payload);
  const signature = cryptoSign(
    null,
    Buffer.from(canonicalPayload, 'utf8'),
    createPrivateKey(mockTsaPrivateKeyPem)
  );

  // Encode as base64 representing token bytes
  const tokenJson = JSON.stringify({
    payload,
    signature: signature.toString('base64'),
    tsaCertId: MOCK_TSA_CERT_ID,
  });
  const rawDerBase64 = Buffer.from(tokenJson, 'utf8').toString('base64');

  return {
    format: 'RFC3161_DER_BASE64_SIMULATED',
    payload,
    tsaCertificateId: MOCK_TSA_CERT_ID,
    tsaPublicKeyPem: MOCK_TSA_PUBLIC_KEY_PEM,
    signatureBase64: signature.toString('base64'),
    rawDerBase64,
  };
}

/**
 * Validates a signed RFC 3161 timestamp token against an evidence file digest.
 */
export function verifyTimestampToken(
  token: SignedTimestampToken,
  expectedSha256DigestHex: string,
  trustedTsaPublicKeys: Record<string, string>
): TimestampVerificationResult {
  try {
    if (!token || !token.payload || !token.signatureBase64) {
      return {
        isValid: false,
        status: 'INVALID',
        tsaName: 'Unknown',
        isDevelopmentMock: false,
        explanation: 'Malformed or missing timestamp token payload.',
      };
    }

    // Verify hash imprint match
    if (token.payload.messageImprint.hashedMessageHex.toLowerCase() !== expectedSha256DigestHex.toLowerCase()) {
      return {
        isValid: false,
        status: 'IMPRINT_MISMATCH',
        tsaName: token.payload.tsaName,
        genTimeUtc: token.payload.genTimeUtc,
        accuracyMs: token.payload.accuracyMs,
        isDevelopmentMock: token.payload.isDevelopmentMock,
        explanation: `Timestamp token message imprint (${token.payload.messageImprint.hashedMessageHex.slice(0, 16)}...) does not match expected evidence SHA-256 (${expectedSha256DigestHex.slice(0, 16)}...).`,
      };
    }

    // Check trusted TSA public key
    const trustedKey = trustedTsaPublicKeys[token.tsaCertificateId] || (token.payload.isDevelopmentMock ? MOCK_TSA_PUBLIC_KEY_PEM : null);
    if (!trustedKey) {
      return {
        isValid: false,
        status: 'TSA_UNTRUSTED',
        tsaName: token.payload.tsaName,
        genTimeUtc: token.payload.genTimeUtc,
        accuracyMs: token.payload.accuracyMs,
        isDevelopmentMock: token.payload.isDevelopmentMock,
        explanation: `TSA certificate '${token.tsaCertificateId}' is not in the independently trusted TSA registry.`,
      };
    }

    // Verify signature
    const signatureBytes = Buffer.from(token.signatureBase64, 'base64');
    const canonicalPayload = canonicalize(token.payload);
    const validSig = cryptoVerify(
      null,
      Buffer.from(canonicalPayload, 'utf8'),
      createPublicKey(trustedKey),
      signatureBytes
    );

    if (!validSig) {
      return {
        isValid: false,
        status: 'INVALID',
        tsaName: token.payload.tsaName,
        genTimeUtc: token.payload.genTimeUtc,
        accuracyMs: token.payload.accuracyMs,
        isDevelopmentMock: token.payload.isDevelopmentMock,
        explanation: 'Cryptographic signature of the timestamp token failed verification.',
      };
    }

    return {
      isValid: true,
      status: 'VERIFIED',
      tsaName: token.payload.tsaName,
      genTimeUtc: token.payload.genTimeUtc,
      accuracyMs: token.payload.accuracyMs,
      isDevelopmentMock: token.payload.isDevelopmentMock,
      explanation: token.payload.isDevelopmentMock
        ? 'Verified with Development Mock TSA (clearly marked non-production; local testing only).'
        : 'Timestamp token cryptographically verified by trusted authority.',
    };
  } catch (err) {
    return {
      isValid: false,
      status: 'INVALID',
      tsaName: token?.payload?.tsaName || 'Unknown',
      isDevelopmentMock: false,
      explanation: `Verification exception: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}
