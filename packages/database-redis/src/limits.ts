/** Fixed portable resource budgets; advanced workloads require explicit native ownership. */
export const REDIS_LIMITS = Object.freeze({
  pending: 128,
  keyBytes: 1024,
  valueBytes: 1_048_576,
  deleteKeys: 1000,
  timeoutMs: 15_000,
});
