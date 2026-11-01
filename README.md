# PROV-GUARD — Context-Aware Digital Evidence Integrity & Provenance Intelligence

This repository extends the existing Digital Evidence Integrity Vault (DEIV) with an advanced research direction: independently checking the recorded provenance and history of digital evidence, not just re-hashing its bytes. The project is designed as an incremental upgrade that preserves the existing DEIV app.

**Important status note:** the `server/provguard/` folder contains reusable starter utilities, not a fully integrated PROV-GUARD product. The database migrations, API integration, UI workflows, external trusted timestamp provider, package export, and standalone offline CLI must still be implemented and validated. Do not describe those features as complete until they exist and pass tests.

## Google AI Studio development

See [`AI_STUDIO/IMPORT_GUIDE.md`](AI_STUDIO/IMPORT_GUIDE.md) for the current GitHub-based import workflow and [`AI_STUDIO/MASTER_PROMPT.md`](AI_STUDIO/MASTER_PROMPT.md) for the full development specification. Google AI Studio Build mode currently documents importing existing code from GitHub; this ZIP is therefore prepared as a GitHub-ready source bundle rather than a native AI Studio project export.

## PROV-GUARD starter modules

- `server/provguard/merkle.ts` — chunk-level Merkle tree and inclusion proofs.
- `server/provguard/manifest.ts` — validated acquisition manifest and Ed25519 signature helpers.
- `server/provguard/genealogy.ts` — evidence parent/child DAG validation.
- `server/provguard/consistency.ts` — uncertainty-aware, explainable chronology rules.
- `server/provguard/checkpoint.ts` — Ed25519 audit checkpoint helpers.
- `server/provguard/verifier.ts` — offline component-check starter.

A signature verifies a statement made by a particular key; it does not prove that the statement is factually true. A file hash proves byte equality against a digest; it does not establish origin, context, or legal admissibility. Trusted timestamps require a real configured TSA and independently validated trust chain.

---

# Digital Evidence Integrity Vault (DEIV)
**Fundamentals of Information Security — Term Project**

DEIV is a full-stack, digital forensics web application and cryptographic evidence repository engineered to guarantee bitstream integrity, chronological chain-of-custody tracking, and tamper-evident audit log validation.

---

## 1. System Architecture

```
                                  +-----------------------------+
                                  |   React 19 + TypeScript     |
                                  |  Tailwind CSS Forensic UI   |
                                  +--------------+--------------+
                                                 | HTTP / JSON (Bearer Token / Cookie)
                                                 v
                                  +-----------------------------+
                                  |    Express.js Backend       |
                                  |  RBAC Middleware & Security |
                                  +--------------+--------------+
                                                 |
         +---------------------------------------+---------------------------------------+
         |                                       |                                       |
         v                                       v                                       v
+------------------+                   +--------------------+                  +--------------------+
|  node:sqlite DB  |                   |  Node.js Crypto    |                  |  Private Storage   |
| (WAL Mode, ACID) |                   |  SHA-256 & Scrypt  |                  | (UUID, Non-Public) |
| - Users / Roles  |                   | - File Hashing     |                  | - Evidence Files   |
| - Evidence Meta  |                   | - Canonical JSON   |                  | - Pristine Backups |
| - Custody Events |                   | - Password Salts   |                  +--------------------+
| - Audit Chain    |                   | - Node Hash Chain  |
+------------------+                   +--------------------+
```

### Core Security Principles Implemented
1. **Never Trust Client Hashes:** All cryptographic digests (SHA-256) are calculated exclusively on the server from raw byte streams directly read from disk.
2. **Private File Storage:** Evidence files are stored outside the public document root with cryptographically generated UUIDs, preventing direct directory listing or guessing.
3. **Download Integrity Gating:** Files cannot be downloaded unless a live, on-demand SHA-256 recalculation matches the baseline ingestion digest.
4. **Tamper-Evident Hash Chaining:** Audit log entries are linked: `Current_Hash = SHA256(Prev_Hash || Event_ID || Action || Actor_ID || Timestamp || Canonical_JSON)`.
5. **Least-Privilege RBAC:** Administrator, Investigator, and Auditor roles enforced server-side on every protected endpoint.
6. **Path Traversal Defense:** Storage identifiers are strictly validated to prevent `../` directory escapes.

---

## 2. Default Forensic Credentials

For project grading and demonstration, the database initializes with three pre-configured accounts:

| Role | Username | Password | Permissions |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `Admin@DEIV2026!` | Full access, user creation, role assignment, audit chain verification |
| **Investigator** | `investigator` | `Investigator@DEIV2026!` | Evidence acquisition, live integrity check, custody transfer, PDF report |
| **Auditor** | `auditor` | `Auditor@DEIV2026!` | Read-only inspection, audit chain verification, report download |

*(Note: Passwords are hashed using `scrypt` with unique 16-byte random salts and compared via `timingSafeEqual`).*

---

## 3. Prerequisites & Installation

### Prerequisites
- Node.js >= 22.0.0 (includes native `node:sqlite` and streaming crypto)
- npm or bun

### Setup
```bash
# Clone the repository
git clone <repo-url>
cd deiv

# Install dependencies
npm install

# Start development server
npm run dev
```

The application runs on `http://localhost:3000`.

---

## 4. Environment Variables (`.env`)

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PORT` | Listening server port | `3000` |
| `SESSION_SECRET` | Secret key for session entropy | `deiv-forensic-secret-key-32-chars-min` |
| `DB_PATH` | Path to persistent SQLite database | `./data/deiv.db` |
| `VAULT_STORAGE_PATH` | Path to private evidence files | `./vault_storage` |

---

## 5. Automated Test Suite

DEIV includes comprehensive automated tests built using Node's native test runner (`node:test`):

```bash
# Run all unit and integration test suites
npm test
```

### Test Coverage Highlights
- **`tests/crypto.test.ts`**: NIST standard SHA-256 test vectors, scrypt salt randomization, canonical JSON serialization consistency.
- **`tests/integrity_and_audit.test.ts`**: File byte hashing, live tamper detection (single-bit flip), file restoration, audit chain gap detection.
- **`tests/auth_and_roles.test.ts`**: Credential validation, timing-safe checks, role permission matrix.
- **`tests/api_security.test.ts`**: Directory path traversal rejection (`../../etc/passwd`), 0-byte empty file handling, input format validators.
- **`tests/backup_and_recovery.test.ts`**: WAL checkpointing, database snapshot generation, backup restoration, transactional rollback file unlinking.

---

## 6. Backup & Recovery Procedures

### Database Snapshot
```bash
# Create an atomic database backup with SHA-256 checksum
npx tsx server/backup.ts create
```
Backups are saved to `./backups/deiv-backup-<timestamp>.db`.

### Restore Database
```bash
# Restore from a verified backup
npx tsx server/backup.ts restore ./backups/deiv-backup-<timestamp>.db
```

---

## 7. Educational Note: Tamper-Evident vs Immutable

A critical concept emphasized throughout DEIV:
- **Tamper-Evident:** Any modification, deletion, reordering, or insertion of records breaks the cryptographic hash linkage (`prev_entry_hash != expected`), alerting auditors immediately.
- **Not Inherently Immutable:** If an attacker gains unrestricted raw disk/database write privileges on the host server, they could mathematically re-compute the entire chain forward from the point of tampering.
- **Real-World Defense:** True immutability requires multi-party replication, write-once media (WORM), external public timestamp anchoring (e.g., RFC 3161 or blockchain anchoring), and strict host-level operating system access controls.

---

## 8. Manual Acceptance Checklist (Grading Walkthrough)

1. **Sign-In:**
   - Go to `http://localhost:3000`.
   - Click the "Investigator" 1-click button or type `investigator` / `Investigator@DEIV2026!`.
   - Verify that the Dashboard appears with live UTC clock and forensic KPI cards.
2. **Evidence Ingestion:**
   - Navigate to **Ingest Evidence**.
   - Select or drag any file (e.g. document, image, or text file).
   - Enter Case ID `CASE-2026-BETA` and Title.
   - Click **Seal & Store Evidence**.
   - Verify the displayed SHA-256 matches the server-calculated digest.
3. **Integrity Verification & Tamper Simulation:**
   - In the **Evidence Vault**, click **Inspect** on an item.
   - Click **Verify Disk Bytes**; confirm status shows `VERIFIED` (green).
   - Click **Inject 1-Bit File Tampering** (Educational Tool).
   - Click **Verify Disk Bytes** again; confirm status immediately flips to `TAMPER DETECTED` (red).
   - Attempt to click **Download File**; verify that download is strictly gated and blocked!
   - Click **Restore Pristine File**; verify that re-checking brings it back to `VERIFIED`.
4. **Audit Chain Verification:**
   - Navigate to **Tamper-Evident Audit**.
   - Click **Verify Full Audit Chain**; confirm 100% cryptographic continuity.
   - (As Admin) Click **Inject Direct Row Tamper**; re-run verification to see the exact sequence gap caught!
5. **PDF Certificate Export:**
   - Navigate to **Forensic PDF Reports**.
   - Click **Download Certificate**; inspect the resulting PDF certificate with cryptographic seals and custody table.
