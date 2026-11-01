import { createHash } from 'node:crypto';

/**
 * PROV-GUARD Merkle tree (SHA-256, domain separated).
 *
 * This implementation is intentionally small and deterministic for the project.
 * For very large evidence files, replace the in-memory builder with a streaming
 * implementation that persists leaf hashes while preserving this exact format.
 */
export const DEFAULT_CHUNK_SIZE = 1024 * 1024;
const LEAF_DOMAIN = 'PROVGUARD_LEAF_V1\0';
const NODE_DOMAIN = 'PROVGUARD_NODE_V1\0';

export interface MerkleTreeMetadata {
  algorithm: 'SHA-256';
  format: 'PROVGUARD_MERKLE_V1';
  chunkSizeBytes: number;
  fileSizeBytes: number;
  leafCount: number;
  rootHash: string;
  leafHashes: string[];
}

export interface MerkleProofSibling {
  side: 'left' | 'right';
  hash: string;
}

export interface MerkleProof {
  format: 'PROVGUARD_MERKLE_PROOF_V1';
  chunkIndex: number;
  leafCount: number;
  chunkSizeBytes: number;
  fileSizeBytes: number;
  siblings: MerkleProofSibling[];
}

function digest(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

function hashLeaf(chunk: Uint8Array): string {
  return createHash('sha256')
    .update(LEAF_DOMAIN, 'utf8')
    .update(chunk)
    .digest('hex');
}

function hashNode(leftHex: string, rightHex: string): string {
  return createHash('sha256')
    .update(NODE_DOMAIN, 'utf8')
    .update(Buffer.from(leftHex, 'hex'))
    .update(Buffer.from(rightHex, 'hex'))
    .digest('hex');
}

function validateChunkSize(chunkSizeBytes: number): void {
  if (!Number.isSafeInteger(chunkSizeBytes) || chunkSizeBytes <= 0) {
    throw new Error('chunkSizeBytes must be a positive safe integer.');
  }
}

function buildLevels(leafHashes: string[]): string[][] {
  if (leafHashes.length === 0) {
    throw new Error('A Merkle tree must contain at least one leaf.');
  }
  const levels: string[][] = [leafHashes];
  while (levels[levels.length - 1].length > 1) {
    const current = levels[levels.length - 1];
    const next: string[] = [];
    for (let index = 0; index < current.length; index += 2) {
      const left = current[index];
      // Duplicate the final node when a level has an odd number of nodes.
      const right = current[index + 1] ?? left;
      next.push(hashNode(left, right));
    }
    levels.push(next);
  }
  return levels;
}

export function buildMerkleTree(
  data: Uint8Array,
  chunkSizeBytes = DEFAULT_CHUNK_SIZE,
): MerkleTreeMetadata {
  validateChunkSize(chunkSizeBytes);
  const bytes = Buffer.from(data);
  const leafHashes: string[] = [];

  if (bytes.length === 0) {
    leafHashes.push(hashLeaf(new Uint8Array()));
  } else {
    for (let offset = 0; offset < bytes.length; offset += chunkSizeBytes) {
      leafHashes.push(hashLeaf(bytes.subarray(offset, Math.min(offset + chunkSizeBytes, bytes.length))));
    }
  }

  const levels = buildLevels(leafHashes);
  return {
    algorithm: 'SHA-256',
    format: 'PROVGUARD_MERKLE_V1',
    chunkSizeBytes,
    fileSizeBytes: bytes.length,
    leafCount: leafHashes.length,
    rootHash: levels[levels.length - 1][0],
    leafHashes,
  };
}

export function createMerkleProof(
  data: Uint8Array,
  chunkIndex: number,
  chunkSizeBytes = DEFAULT_CHUNK_SIZE,
): { chunk: Buffer; proof: MerkleProof; leafHash: string; rootHash: string } {
  const metadata = buildMerkleTree(data, chunkSizeBytes);
  if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0 || chunkIndex >= metadata.leafCount) {
    throw new Error('chunkIndex is outside the evidence file.');
  }

  const bytes = Buffer.from(data);
  const start = chunkIndex * chunkSizeBytes;
  const chunk = bytes.subarray(start, Math.min(start + chunkSizeBytes, bytes.length));
  const levels = buildLevels(metadata.leafHashes);
  const siblings: MerkleProofSibling[] = [];
  let cursor = chunkIndex;

  for (let levelIndex = 0; levelIndex < levels.length - 1; levelIndex += 1) {
    const level = levels[levelIndex];
    const siblingIndex = cursor % 2 === 0 ? cursor + 1 : cursor - 1;
    const siblingHash = level[siblingIndex] ?? level[cursor];
    siblings.push({ side: cursor % 2 === 0 ? 'right' : 'left', hash: siblingHash });
    cursor = Math.floor(cursor / 2);
  }

  return {
    chunk,
    leafHash: metadata.leafHashes[chunkIndex],
    rootHash: metadata.rootHash,
    proof: {
      format: 'PROVGUARD_MERKLE_PROOF_V1',
      chunkIndex,
      leafCount: metadata.leafCount,
      chunkSizeBytes,
      fileSizeBytes: bytes.length,
      siblings,
    },
  };
}

export function verifyMerkleProof(
  chunk: Uint8Array,
  proof: MerkleProof,
  expectedRootHash: string,
): boolean {
  try {
    if (proof.format !== 'PROVGUARD_MERKLE_PROOF_V1') return false;
    if (!Number.isSafeInteger(proof.leafCount) || proof.leafCount < 1) return false;
    if (!Number.isSafeInteger(proof.chunkIndex) || proof.chunkIndex < 0 || proof.chunkIndex >= proof.leafCount) return false;
    validateChunkSize(proof.chunkSizeBytes);
    if (!/^[a-f0-9]{64}$/i.test(expectedRootHash)) return false;
    if (chunk.byteLength > proof.chunkSizeBytes) return false;

    const expectedChunkLength = proof.chunkIndex === proof.leafCount - 1
      ? proof.fileSizeBytes - proof.chunkIndex * proof.chunkSizeBytes
      : proof.chunkSizeBytes;
    if (chunk.byteLength !== expectedChunkLength) return false;

    let current = hashLeaf(chunk);
    let cursor = proof.chunkIndex;
    let width = proof.leafCount;
    let siblingPosition = 0;

    while (width > 1) {
      const sibling = proof.siblings[siblingPosition];
      if (!sibling || !/^[a-f0-9]{64}$/i.test(sibling.hash)) return false;
      const expectedSide = cursor % 2 === 0 ? 'right' : 'left';
      if (sibling.side !== expectedSide) return false;
      // For an odd final node, the proof must duplicate that node itself.
      if (cursor % 2 === 0 && cursor + 1 >= width && sibling.hash !== current) return false;
      current = sibling.side === 'left'
        ? hashNode(sibling.hash, current)
        : hashNode(current, sibling.hash);
      cursor = Math.floor(cursor / 2);
      width = Math.ceil(width / 2);
      siblingPosition += 1;
    }

    if (siblingPosition !== proof.siblings.length) return false;
    return current.toLowerCase() === expectedRootHash.toLowerCase();
  } catch {
    return false;
  }
}

/** Ordinary whole-file SHA-256, included for comparison with the Merkle root. */
export function sha256Bytes(data: Uint8Array): string {
  return digest(data);
}
