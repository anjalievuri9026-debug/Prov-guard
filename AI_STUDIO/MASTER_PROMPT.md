# MASTER BUILD PROMPT — PROV-GUARD

You are extending an existing React + TypeScript + Express digital forensics project named Digital Evidence Integrity Vault (DEIV). Upgrade it into **PROV-GUARD: Context-Aware Digital Evidence Integrity & Provenance Intelligence**.

Do not replace the project with a generic dashboard or start over. First inspect the full repository, understand the current routes, database, authentication, UI navigation, tests, storage layer, and PDF report implementation. Preserve working DEIV behavior and evolve the current application in small, testable changes.

## Product thesis

A matching SHA-256 digest proves only that the bytes match a recorded digest. It does not, by itself, prove who created the file, where it came from, whether acquisition was correctly performed, whether its custody history is complete, or whether the underlying events are truthful. PROV-GUARD must report these dimensions separately and never label evidence simply as “genuine,” “fake,” “authentic,” or “court-admissible.”

The core research contribution is a **contradiction-aware evidence provenance engine** that connects binary integrity, acquisition context, signed provenance, transformation lineage, chronology checks, and an offline independent verifier.

## Existing foundation to preserve

- React 19 + TypeScript + Vite frontend.
- Express + TypeScript backend.
- SQLite using Node's built-in `node:sqlite`.
- Existing authentication and Administrator / Investigator / Auditor role model.
- Existing private evidence storage, SHA-256 verification, custody events, audit hash chain, backup/recovery, and PDF report features.
- Existing visual identity: dark forensic command-center styling, unless a clearer accessible treatment is needed.
- Existing test suite and demo flows.

The repository already contains reusable starter utilities in `server/provguard/` and tests in `tests/provguard.test.ts`. Read and reuse them; do not create duplicate implementations. Fix or extend them as necessary.

## Required architecture and modules

### 1. Acquisition Passport

For every newly acquired evidence item, create a versioned JSON acquisition manifest containing:
- manifest schema version and stable evidence/case identifiers;
- original filename, MIME type, byte size, server-calculated SHA-256;
- acquisition time, server-recorded time, timezone, source device/category and source description;
- acquisition method, tool name/version, operator ID and optional independent witness ID;
- clock uncertainty and timestamp-source information;
- metadata claims with explicit origin labels (`embedded`, `operator`, `system`, or `external`).

Validate all fields. The server must calculate hashes from stored bytes; never trust a browser-supplied digest. Persist the exact canonical manifest used for signing. Existing evidence without a passport must be marked `LEGACY_UNATTESTED` or equivalent, not silently backfilled as if its original acquisition had been witnessed.

### 2. Ed25519 manifest signing and key management

- Sign canonical manifest bytes with Ed25519.
- Store algorithm, key ID, signature, and manifest version.
- Keep private signing keys in server-side secrets or a protected key store; never send private keys to the browser or commit them.
- Maintain a trusted public-key registry with key ID, public key, owner, creation/expiry/revocation metadata, and status.
- A verifier must use a public key trusted independently of the evidence package. A public key embedded only in the same package is not a trust anchor.
- Include key rotation and revocation states in the UI and report.
- Never generate a fake signature or display `PASS` if a key is unavailable.

### 3. Chunk-level Merkle integrity

- Use the starter implementation in `server/provguard/merkle.ts` as the defined format unless testing identifies a defect.
- Store chunk size, file size, leaf count, each leaf hash (or a scalable index to it), tree format version, and root hash.
- Provide inclusion-proof generation and independent proof verification for a selected chunk.
- Verify odd-leaf behavior and empty-file behavior with tests.
- The UI must show which chunk failed, where a proof exists, and the Merkle root. It must not call the Merkle root a substitute for the whole-file SHA-256.
- For large files, implement streaming/chunked processing. Do not read an unbounded evidence file into memory.

### 4. Evidence Genealogy Graph

Represent each evidence artifact as a node with artifact ID, SHA-256, size, creation time, and parent artifact IDs. Represent each transformation as a first-class record with:
- transformation ID;
- parent artifact ID(s) and expected parent digest(s);
- child artifact ID and digest;
- tool name/version and transformation category;
- canonicalized parameters or a digest of sensitive parameters;
- operator identity, event time, and optional witness/signature.

Build a directed acyclic graph (DAG), detect missing parents, duplicate IDs, malformed digests, cycles, and inconsistent transformation links. Support an original file → extracted segment → redacted copy workflow. Never overwrite the original artifact. Keep original and derived artifacts distinct.

### 5. Context contradiction engine

Implement deterministic, explainable rules—not an opaque AI verdict. Compare only explicit, sourced observations and chronology constraints. Each observation must record its source, timestamp, timezone/UTC normalization, uncertainty, and provenance. Results must be one of:
- `CONSISTENT` — recorded order meets the declared rule;
- `CONFLICT` — even after stated uncertainty, the required order is impossible;
- `AMBIGUOUS` — nominal times conflict or overlap in a way that prevents a firm conclusion;
- `UNKNOWN` — required facts are missing, invalid, or lack usable source context.

Every finding must explain the compared facts and the rule. Allow investigator notes and a reviewed/resolved state, but never erase the original finding. A timestamp mismatch is a reason to investigate, not automatic proof of tampering. Distinguish filesystem metadata, embedded metadata, operator-entered times, server receipt times, and independent trusted timestamp tokens.

### 6. Independent checkpoints and trusted timestamps

- Sign audit-chain checkpoints with Ed25519, including sequence number and audit-head hash.
- Export checkpoint records so they can be retained outside the application host.
- Explain that a locally stored signed checkpoint is only independently useful if its public key is trusted out-of-band and the checkpoint is retained in a separate trust domain.
- Add an adapter interface for an RFC 3161 Time-Stamp Authority (TSA). The app may report `VERIFIED` only after cryptographic token validation against configured trusted TSA certificates and imprint comparison.
- Until a real TSA provider and certificate trust configuration are set, display `NOT_CONFIGURED` / `UNKNOWN`. Never substitute `new Date()` or the application server clock for an independent trusted timestamp.
- Do not claim that blockchain, a local hash chain, or a signature alone makes the database immutable.

### 7. Offline Independent Verifier

Create a downloadable verification package with a versioned manifest, signature, public-key identifiers, Merkle metadata/proofs, genealogy records, relevant audit events, checkpoints, and a README. Include the evidence bytes only when an authorized user explicitly chooses to include them; otherwise include digests and references.

Create a separate CLI or standalone verifier that can run on another machine without connecting to the DEIV database. It must:
- calculate SHA-256 directly from supplied evidence bytes;
- compare byte size and digest with the signed manifest;
- verify the manifest signature against a user-supplied trusted public-key registry;
- verify Merkle root and selected inclusion proofs;
- validate genealogy structure and transformations;
- verify available signed audit checkpoints;
- validate RFC 3161 tokens only when configured trust material exists;
- output machine-readable JSON and a readable HTML/PDF report;
- separate `PASS`, `FAIL`, `UNKNOWN`, `NOT_CONFIGURED`, and `SKIPPED` states.

The offline verifier must not call the application's database or trust data fetched from the application server during verification.

### 8. Multidimensional verification dashboard

Replace the single green `VERIFIED` concept in the advanced view with independent dimensions:
- Byte integrity: `PASS` / `FAIL` / `UNKNOWN`.
- Manifest signature: `PASS` / `FAIL` / `UNKNOWN`.
- Provenance completeness: `COMPLETE` / `PARTIAL` / `MISSING`.
- Custody continuity: `CONTINUOUS` / `GAP` / `UNKNOWN`.
- Context consistency: `CONSISTENT` / `CONFLICT` / `AMBIGUOUS` / `UNKNOWN`.
- Trusted timestamp: `VERIFIED` / `NOT_CONFIGURED` / `UNKNOWN`.
- Genealogy: `VALID` / `INVALID` / `INCOMPLETE`.

Do not collapse these into a claim of authenticity. An overall label may be `COMPONENT_CHECKS_PASSED` or `REVIEW_REQUIRED`, with a visible note explaining exactly what was and was not checked.

### 9. User interface

Add navigation/pages or tabs for:
- Acquisition Passport;
- Evidence Lineage (interactive graph and event list);
- Context Findings (rule, evidence, uncertainty, explanation, reviewer disposition);
- Merkle Inspector (root, chunk list, inclusion proof);
- Signing Keys & Checkpoints;
- Offline Verification Package / Verifier.

Preserve existing Dashboard, Evidence Vault, Upload, Evidence Detail, Custody, Audit, Reports, and Users screens. Add filters, pagination, accessible color contrast, empty states, loading states, clear errors, and confirmation for destructive demo actions. Show synthetic sample data labels prominently.

## Suggested API surface

Follow the existing Express router and RBAC patterns. Use validated request schemas and server-side authorization for every endpoint.

- `POST /api/provguard/evidence/:id/manifest` — create, validate and sign a passport.
- `GET /api/provguard/evidence/:id/manifest` — retrieve passport and signature metadata.
- `POST /api/provguard/evidence/:id/merkle` — calculate/store Merkle metadata.
- `GET /api/provguard/evidence/:id/merkle/proof/:chunkIndex` — return a proof for a chunk.
- `POST /api/provguard/evidence/:id/lineage` — record a derived artifact/transformation.
- `GET /api/provguard/evidence/:id/lineage` — return lineage subgraph.
- `POST /api/provguard/evidence/:id/context-check` — run deterministic chronology rules.
- `POST /api/provguard/checkpoints` — sign an audit checkpoint.
- `GET /api/provguard/evidence/:id/offline-package` — export a verification package.
- `POST /api/provguard/verify-package` — run server-side verification for demo convenience; the independent CLI must still work offline.

These are proposed routes. Adjust naming to match existing patterns, but document any changes.

## Database and migration requirements

Use idempotent schema migrations compatible with the existing SQLite database. Do not drop or rename current tables. Add normalized tables for acquisition manifests, trusted signing keys, Merkle metadata/chunks, artifact nodes, transformation records, context observations/findings, signed checkpoints, and timestamp tokens. Add indexes for evidence ID, case ID, sequence, and relevant timestamps. Preserve foreign-key integrity. Provide migration tests and rollback guidance. Do not store private keys in SQLite as plaintext.

## Security and privacy requirements

- Keep uploaded evidence private and outside the public static directory.
- Use server-calculated hashes, path-safe storage identifiers, file-size limits, MIME sniffing where practical, and strict input validation.
- Enforce roles server-side; auditors remain read-only.
- Keep secrets server-side. Do not put Gemini API keys, private signing keys, session secrets, or certificates in frontend bundles.
- Never send uploaded evidence bytes or sensitive content to Gemini. Any optional AI explanation may receive only minimized, redacted finding metadata and must not determine cryptographic results.
- Record access, export, verification, key change, and reviewer disposition events in the audit log.
- Use only synthetic demo evidence and fake identities in seeded data.
- Treat the current demo credentials as local-only and prevent their use in production configuration.

## Required tests and demo scenarios

Create or extend automated tests for:
1. SHA-256 and byte-size mismatch.
2. Valid, invalid, and unknown-key manifest signatures.
3. Manifest mutation after signing.
4. Merkle proofs for first, middle, last, odd-leaf, single-leaf, and empty-file cases.
5. Modified chunk and modified Merkle root.
6. Valid genealogy, missing parent, duplicate ID, and cycle.
7. Chronology consistent, definite conflict, uncertainty overlap/ambiguous, and missing observation.
8. Valid/invalid checkpoint signature and wrong public key.
9. Offline verifier works without DB/network access.
10. RBAC denies unauthorized writes and exports.
11. Migration preserves existing DEIV evidence, users, custody and audit history.
12. Offline package tampering is detected.

Add a guided synthetic demo that shows: acquire original → sign passport → create Merkle root → derive a redacted child → view lineage → trigger a synthetic context contradiction → export package → verify package offline. Mark every simulated finding and sample as synthetic.

## Development workflow — do these in order

**Phase 0 — Repository assessment:** summarize current architecture, identify risks, run existing tests/build, and list migration plan. Do not modify files until you understand current flows.

**Phase 1 — Foundation:** validate and test the starter modules in `server/provguard/`; implement migrations and backend services. Keep the app running.

**Phase 2 — API integration:** add routes, role checks, audit events, and API tests.

**Phase 3 — UI integration:** add the modules to existing navigation and pages; maintain the existing dark forensic UI.

**Phase 4 — Offline verifier:** implement package export and standalone offline CLI/report, then verify it without starting the web server.

**Phase 5 — Hardening and validation:** run type checks, all tests, production build, migration test, and acceptance walkthrough. Fix all failures before claiming completion.

At the end of each phase, report exactly which files changed, commands run, test results, unresolved limitations, and how to demonstrate the feature. Do not claim a feature is implemented until the code path and tests exist. Prefer small incremental changes over rewriting the repository.

## Definition of done

A working React/Express application with the above features integrated, idempotent migrations, meaningful tests, a truly offline verifier, synthetic end-to-end demo, setup documentation, a security limitations section, and screenshots captured from the running application. Clearly list anything that remains unimplemented (especially external TSA integration or key custody that requires deployment configuration).
