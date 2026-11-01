# PROV-GUARD implementation specification

## Proposed data model

Names are suggested. Adapt them to existing naming conventions without deleting legacy tables.

| Table | Purpose | Important fields |
|---|---|---|
| `acquisition_manifests` | Immutable versions of passports | `id`, `evidence_id`, `schema_version`, `canonical_json`, `manifest_sha256`, `signature_algorithm`, `signer_key_id`, `signature_base64`, `created_at_utc` |
| `trusted_signing_keys` | Public key trust registry | `key_id`, `public_key_pem`, `owner_label`, `status`, `valid_from_utc`, `valid_until_utc`, `revoked_at_utc` |
| `merkle_trees` | File Merkle metadata | `id`, `evidence_id`, `format_version`, `chunk_size_bytes`, `file_size_bytes`, `leaf_count`, `root_hash`, `created_at_utc` |
| `merkle_leaves` | Leaf hashes for proofs | `tree_id`, `leaf_index`, `chunk_size_bytes`, `leaf_hash` |
| `artifact_nodes` | Original and derived artifacts | `artifact_id`, `evidence_id`, `sha256`, `size_bytes`, `created_at_utc`, `description` |
| `artifact_parents` | Parent-child edges | `child_artifact_id`, `parent_artifact_id` |
| `transformations` | Transformation receipt | `id`, `child_artifact_id`, `tool_name`, `tool_version`, `parameters_canonical`, `operator_id`, `performed_at_utc`, `signature_key_id`, `signature_base64` |
| `context_observations` | Sourced facts used in rules | `id`, `evidence_id`, `label`, `value_utc`, `source_type`, `source_reference`, `uncertainty_ms` |
| `context_findings` | Rule outcomes and review status | `id`, `evidence_id`, `rule_id`, `status`, `explanation`, `review_state`, `reviewer_id`, `reviewed_at_utc` |
| `audit_checkpoints` | Signed audit heads | `id`, `audit_sequence`, `audit_head_hash`, `created_at_utc`, `signer_key_id`, `signature_base64`, `external_anchor_reference` |
| `timestamp_tokens` | RFC 3161 token evidence | `id`, `evidence_id`, `imprint_sha256`, `token_der_base64`, `tsa_certificate_id`, `verification_status`, `verified_at_utc` |

Use transactions for operations that create an artifact node, transformation receipt, custody event and audit event together. Store private signing keys outside the database in a supported secret/key-management service. Do not store evidence bytes in SQLite.

## Verification state vocabulary

| Dimension | Allowed states |
|---|---|
| Byte integrity | `PASS`, `FAIL`, `UNKNOWN` |
| Manifest signature | `PASS`, `FAIL`, `UNKNOWN` |
| Provenance completeness | `COMPLETE`, `PARTIAL`, `MISSING` |
| Custody continuity | `CONTINUOUS`, `GAP`, `UNKNOWN` |
| Context consistency | `CONSISTENT`, `CONFLICT`, `AMBIGUOUS`, `UNKNOWN` |
| Trusted timestamp | `VERIFIED`, `NOT_CONFIGURED`, `UNKNOWN`, `INVALID` |
| Genealogy | `VALID`, `INVALID`, `INCOMPLETE` |

Do not derive evidence authenticity or legal admissibility from these states.

## Trust boundaries

- Browser: untrusted input and presentation only.
- Application server: validates requests and calculates digests; it is still an administrative trust domain.
- Evidence storage: private; restrict write access and record access.
- Signing key store: separate from ordinary application data and database backups.
- External timestamp authority / independent checkpoint store: separate trust domain and configured explicitly.
- Offline verifier: runs independently, trusts only public keys and trust configuration supplied by its operator.

## Timestamp interpretation

Every time value must identify its source and known uncertainty. The application server clock is an observation, not an independent trusted timestamp. Embedded file timestamps can be altered and must be treated as claims. RFC 3161 verification must validate the signed token, message imprint, TSA certificate chain and applicable trust policy; do not mark a token trusted just because a token-shaped file exists.

## Offline package layout proposal

```text
provguard-package/
  package.json
  README.txt
  evidence/                 # optional, only when explicitly included
  manifests/
    acquisition.json
    acquisition.sig.json
  merkle/
    tree.json
    proofs/
  genealogy/
    artifacts.json
    transformations.json
  audit/
    events.json
    checkpoints.json
  timestamps/
    tokens/                 # original TSA token bytes when present
  trust/
    key-identifiers.json    # identifiers only; verifier supplies trusted keys
  reports/
```

The package must record its own schema version. Do not include a private key. Do not package a public key as trusted merely because it is included; the verifier operator must select the trust registry independently.
