# Project context for AI Studio

## Starting point

This repository is the user's existing Digital Evidence Integrity Vault (DEIV), not a blank template. It already contains:

- React/TypeScript/Vite UI with Dashboard, Vault, Upload, Evidence Detail, Custody, Audit, Reports and Users pages.
- Express API, role-based authentication, evidence upload/private storage, server-calculated SHA-256, custody events, local hash-chained audit logs, backup/recovery and PDF reports.
- SQLite database using Node's `node:sqlite` module.
- Node test-runner tests for crypto, roles, evidence integrity, audit chain, API security and backup/recovery.

## New starter code included

`server/provguard/` includes reusable initial functions for:
- SHA-256 chunk Merkle tree construction and inclusion proofs;
- Ed25519 acquisition manifest signatures;
- evidence genealogy DAG validation;
- uncertainty-aware chronology checks;
- Ed25519 audit checkpoint signatures;
- offline verification of bytes, manifest signature and optional Merkle/genealogy inputs.

`tests/provguard.test.ts` exercises the starter utilities.

These modules are a foundation, not a fully integrated application feature. They must be reviewed, tested, wired into database migrations, API routes, UI, package export and standalone offline verification before the project can claim complete PROV-GUARD functionality.

## Runtime note

The existing project uses `node:sqlite`, which requires a sufficiently recent Node runtime. The current project README specifies Node.js 22 or later. Keep the runtime requirement explicit and confirm the AI Studio full-stack environment supports the API used by the project. If not, propose a compatible persistence adapter and migration path without deleting user data.
