# Changelog

## 0.1.0

- Verify corrupted durable records, indexes, counters, epochs and receipts,
  identity-provider output, expiry and bounded activity retries with real PostgreSQL checks.
- Capture configured provider methods without evaluating callable metadata, and
  reject proxy callbacks and unbounded prototype traversal before session authorization.
- Add shared-state server sessions with atomic renewal, per-owner quotas and
  monotonic global revocation epochs.
- Require independent runtime authentication and authorization, preserving
  original authentication and MFA metadata while resolving current privileges.
- Bound provider concurrency and deadlines, fail closed on backend failures
  and retain ambiguous-write outcomes without exposing secrets.
