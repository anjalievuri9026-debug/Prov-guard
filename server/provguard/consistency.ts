export interface TimeObservation {
  id: string;
  label: string;
  timestampUtc: string;
  source: 'embedded' | 'operator' | 'server' | 'trusted_timestamp' | 'external' | 'unknown';
  uncertaintyMs?: number;
}

export interface ChronologyConstraint {
  beforeId: string;
  afterId: string;
  explanation: string;
}

export interface ChronologyFinding {
  beforeId: string;
  afterId: string;
  status: 'CONSISTENT' | 'CONFLICT' | 'AMBIGUOUS' | 'UNKNOWN';
  explanation: string;
  observedBeforeUtc?: string;
  observedAfterUtc?: string;
}

/**
 * Rule-based chronology checks. A conflict means the recorded time intervals
 * make the required order impossible; it is not proof of intentional alteration.
 */
export function assessChronology(
  observations: readonly TimeObservation[],
  constraints: readonly ChronologyConstraint[],
): ChronologyFinding[] {
  const byId = new Map(observations.map((observation) => [observation.id, observation]));

  return constraints.map((constraint) => {
    const before = byId.get(constraint.beforeId);
    const after = byId.get(constraint.afterId);
    if (!before || !after) {
      return { beforeId: constraint.beforeId, afterId: constraint.afterId, status: 'UNKNOWN', explanation: `${constraint.explanation} Required observation is missing.` };
    }

    const beforeMs = Date.parse(before.timestampUtc);
    const afterMs = Date.parse(after.timestampUtc);
    const beforeUncertainty = before.uncertaintyMs ?? 0;
    const afterUncertainty = after.uncertaintyMs ?? 0;
    if (!Number.isFinite(beforeMs) || !Number.isFinite(afterMs) ||
        !Number.isFinite(beforeUncertainty) || !Number.isFinite(afterUncertainty) ||
        beforeUncertainty < 0 || afterUncertainty < 0) {
      return {
        beforeId: before.id,
        afterId: after.id,
        status: 'UNKNOWN',
        explanation: `${constraint.explanation} One or more timestamps or uncertainty values are invalid.`,
        observedBeforeUtc: before.timestampUtc,
        observedAfterUtc: after.timestampUtc,
      };
    }

    const beforeEarliest = beforeMs - beforeUncertainty;
    const beforeLatest = beforeMs + beforeUncertainty;
    const afterEarliest = afterMs - afterUncertainty;
    const afterLatest = afterMs + afterUncertainty;

    if (beforeEarliest > afterLatest) {
      return {
        beforeId: before.id,
        afterId: after.id,
        status: 'CONFLICT',
        explanation: `${constraint.explanation} Even after accounting for recorded clock uncertainty, the required order is contradicted. Review source clocks and acquisition notes.`,
        observedBeforeUtc: before.timestampUtc,
        observedAfterUtc: after.timestampUtc,
      };
    }

    if (beforeMs > afterMs) {
      return {
        beforeId: before.id,
        afterId: after.id,
        status: 'AMBIGUOUS',
        explanation: `${constraint.explanation} The nominal timestamps are reversed, but their uncertainty intervals overlap; do not draw a definitive conclusion.`,
        observedBeforeUtc: before.timestampUtc,
        observedAfterUtc: after.timestampUtc,
      };
    }

    return {
      beforeId: before.id,
      afterId: after.id,
      status: 'CONSISTENT',
      explanation: `${constraint.explanation} The recorded order is consistent with the declared uncertainty.`,
      observedBeforeUtc: before.timestampUtc,
      observedAfterUtc: after.timestampUtc,
    };
  });
}
