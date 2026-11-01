export interface EvidenceArtifactNode {
  artifactId: string;
  sha256: string;
  parentArtifactIds: string[];
  createdAtUtc: string;
  description?: string;
}

export interface GenealogyFinding {
  code: 'DUPLICATE_ARTIFACT_ID' | 'INVALID_SHA256' | 'MISSING_PARENT' | 'CYCLE_DETECTED' | 'INVALID_TIMESTAMP';
  severity: 'ERROR' | 'WARNING';
  artifactId?: string;
  message: string;
}

export interface GenealogyValidation {
  isStructurallyValid: boolean;
  topologicalOrder: string[];
  findings: GenealogyFinding[];
}

/** Validate a directed parent -> child evidence lineage graph. */
export function validateEvidenceGenealogy(nodes: readonly EvidenceArtifactNode[]): GenealogyValidation {
  const findings: GenealogyFinding[] = [];
  const byId = new Map<string, EvidenceArtifactNode>();

  for (const node of nodes) {
    if (!node.artifactId?.trim()) {
      findings.push({ code: 'DUPLICATE_ARTIFACT_ID', severity: 'ERROR', message: 'An artifact has an empty identifier.' });
      continue;
    }
    if (byId.has(node.artifactId)) {
      findings.push({ code: 'DUPLICATE_ARTIFACT_ID', severity: 'ERROR', artifactId: node.artifactId, message: `Artifact identifier ${node.artifactId} occurs more than once.` });
      continue;
    }
    byId.set(node.artifactId, node);
    if (!/^[a-f0-9]{64}$/i.test(node.sha256 ?? '')) {
      findings.push({ code: 'INVALID_SHA256', severity: 'ERROR', artifactId: node.artifactId, message: 'Artifact SHA-256 is malformed.' });
    }
    if (!Number.isFinite(Date.parse(node.createdAtUtc))) {
      findings.push({ code: 'INVALID_TIMESTAMP', severity: 'WARNING', artifactId: node.artifactId, message: 'Artifact creation time is missing or not parseable.' });
    }
  }

  for (const node of nodes) {
    for (const parentId of node.parentArtifactIds ?? []) {
      if (!byId.has(parentId)) {
        findings.push({ code: 'MISSING_PARENT', severity: 'ERROR', artifactId: node.artifactId, message: `Parent artifact ${parentId} is not present in this genealogy package.` });
      }
    }
  }

  const state = new Map<string, 0 | 1 | 2>();
  const order: string[] = [];
  const reportedCycles = new Set<string>();

  const visit = (id: string): void => {
    const currentState = state.get(id) ?? 0;
    if (currentState === 2) return;
    if (currentState === 1) {
      if (!reportedCycles.has(id)) {
        reportedCycles.add(id);
        findings.push({ code: 'CYCLE_DETECTED', severity: 'ERROR', artifactId: id, message: `A cycle exists in the evidence lineage near ${id}.` });
      }
      return;
    }
    state.set(id, 1);
    const node = byId.get(id);
    for (const parentId of node?.parentArtifactIds ?? []) {
      if (byId.has(parentId)) visit(parentId);
    }
    state.set(id, 2);
    order.push(id);
  };

  for (const id of byId.keys()) visit(id);
  const hasErrors = findings.some((finding) => finding.severity === 'ERROR');
  return {
    isStructurallyValid: !hasErrors,
    topologicalOrder: hasErrors ? [] : order,
    findings,
  };
}
