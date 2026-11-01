# Follow-up prompts for Google AI Studio

Paste these one at a time after the master prompt. Let the agent complete and validate each phase before requesting the next one.

## Phase 0 — Assess before changing code

Read the entire project and the master prompt. Do not edit files yet. Run the existing test suite and production build if the environment permits. Explain the current routes, database tables, authentication/RBAC flow, evidence storage, audit chain, frontend navigation and reporting. Identify compatibility risks with the Google AI Studio Node.js runtime, especially the `node:sqlite` requirement. Propose idempotent migrations and an implementation order. List any existing tests that are failing.

## Phase 1 — Backend foundation

Implement Phase 1 only: review and correct the reusable utilities in `server/provguard/`, add idempotent SQLite migrations, services and safe key configuration. Preserve old DEIV data and routes. Add focused unit tests. Do not change the UI yet. Run typecheck and tests and report exact outcomes.

## Phase 2 — API and authorization

Implement the PROV-GUARD API endpoints from the master prompt. Use the project's existing auth middleware and role model. Add audit events to all important operations. Enforce read-only auditor permissions. Add API integration tests including unauthorized and malformed requests. Do not change the visual design yet.

## Phase 3 — Frontend integration

Integrate Acquisition Passport, Evidence Lineage, Context Findings, Merkle Inspector, Signing Keys & Checkpoints, and Offline Verification into the existing React navigation and detail views. Keep the visual design consistent with the existing forensic dashboard. Show independent verification dimensions, not a single authenticity verdict. Include empty/loading/error states and synthetic-data labels. Do not add decorative graphs that are not backed by real API data.

## Phase 4 — Offline verifier

Build a standalone verifier command and versioned offline package format. It must run on a machine without this application, without the SQLite database and without a network connection. Require trusted public keys to be supplied out-of-band. Validate digests, signatures, Merkle roots/proofs, genealogy, audit checkpoints and configured timestamp tokens. Generate JSON and readable reports. Add tests that tamper with each package component.

## Phase 5 — Final validation and demonstration

Run dependency/type checks, all automated tests, production build, database migration tests, and the synthetic end-to-end walkthrough. Fix all failures. Capture screenshots of the running UI for the project report. Update README and docs with exact setup steps, demo credentials (clearly marked local-only), API documentation, architecture, threat model, limitations, and test results. Do not claim RFC 3161 integration unless actual TSA token verification and trust configuration are implemented and tested.
