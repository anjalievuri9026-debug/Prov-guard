export type UserRole = 'Administrator' | 'Investigator' | 'Auditor';

export interface User {
  id: string;
  username: string;
  email: string;
  fullName: string;
  role: UserRole;
  createdAt?: string;
}

export type EvidenceStatus = 'VERIFIED' | 'TAMPER_DETECTED' | 'UNVERIFIED' | 'MISSING_FILE' | 'VERIFICATION_FAILED';

export interface Evidence {
  id: string;
  case_id: string;
  title: string;
  original_filename: string;
  storage_filename: string;
  mime_type: string;
  file_size_bytes: number;
  original_sha256: string;
  uploader_id: string;
  uploader_name: string;
  uploader_role: string;
  created_at: string;
  status: EvidenceStatus;
  last_verified_at: string | null;
  last_calculated_sha256: string | null;
  notes: string;
  tags: string;
  is_tampered_demo: number;
}

export interface CustodyEvent {
  id: string;
  evidence_id: string;
  action: string;
  actor_id: string;
  actor_name: string;
  actor_role: string;
  timestamp_utc: string;
  details_json: string;
  created_at: string;
  case_id?: string;
  evidence_title?: string;
}

export interface AuditLogEntry {
  id: number;
  event_id: string;
  sequence_num: number;
  actor_id: string;
  actor_name: string;
  actor_role: string;
  action: string;
  evidence_id: string | null;
  timestamp_utc: string;
  details_canonical: string;
  prev_entry_hash: string;
  current_entry_hash: string;
}

export interface ChainVerificationResult {
  isValid: boolean;
  totalEntries: number;
  genesisHash: string;
  tipHash: string | null;
  verifiedCount: number;
  brokenAtSequence?: number;
  brokenEventId?: string;
  reason?: string;
  discrepancyType?: 'HASH_MISMATCH' | 'PREV_HASH_LINK_BROKEN' | 'SEQUENCE_GAP' | 'GENESIS_TAMPER';
  educationalExplanation: string;
}

export interface DashboardMetrics {
  metrics: {
    totalEvidence: number;
    verifiedCount: number;
    tamperedCount: number;
    unverifiedCount: number;
    missingCount: number;
    totalCustodyEvents: number;
    totalAuditLogs: number;
  };
  chainHealth: {
    isValid: boolean;
    totalEntries: number;
    tipHash: string | null;
    reason?: string;
  };
  recentEvidence: Evidence[];
  recentCustody: CustodyEvent[];
  caseSummaries: { case_id: string; count: number; last_updated: string }[];
}
