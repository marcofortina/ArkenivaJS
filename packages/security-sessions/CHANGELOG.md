# Changelog

## 0.1.0

- Add shared-state server sessions with atomic renewal, per-owner quotas and
  monotonic global revocation epochs.
- Require independent runtime authentication and authorization, preserving
  original authentication and MFA metadata while resolving current privileges.
- Bound provider concurrency and deadlines, fail closed on backend failures
  and retain ambiguous-write outcomes without exposing secrets.
