# Test and demonstration plan

## Synthetic walkthrough

1. Sign in using a local-only demonstration account.
2. Create a synthetic case and upload a synthetic text or image file.
3. Generate its Acquisition Passport; review source, tool, operator, timezone and uncertainty fields.
4. Generate the SHA-256 digest and Merkle tree; inspect one chunk proof.
5. Create a derived artifact record (for example, a shortened synthetic text extract) and attach a transformation receipt.
6. View original → derived lineage.
7. Add synthetic timestamp observations that intentionally conflict with a declared chronology rule. The system should show `CONFLICT` or `AMBIGUOUS` with a rule explanation, never a claim that tampering is proven.
8. Sign an audit checkpoint and export the offline verification package.
9. Run the offline verifier on the export with an independently supplied trusted public key.
10. Create a copy of the package and change one byte in the evidence or manifest. Run the verifier again; it should report the corresponding failed component.

## Evidence to capture for a project demonstration

- Dashboard with the independent verification dimensions.
- Acquisition passport and signature validation view.
- Merkle tree root and one successful inclusion proof.
- Lineage graph with one derived artifact.
- Context contradiction finding and reviewer note.
- Audit checkpoint and key trust status.
- Offline verifier successful report.
- Offline verifier report after a synthetic tamper test.

All test files and screenshots must use synthetic data. Do not use real private records as demo fixtures.
