# Changelog

## 0.1.0

- Verify malformed durable records, owner guards, rate counters, write receipts,
  expired retained credentials and operation boundaries, including actual PostgreSQL corruption.
- Capture configured provider methods without executing callable metadata, and reject
  proxy providers and unbounded prototype traversal before authorization or storage work.
- Add scoped API key issuance, verification, atomic rotation/revocation and bounded owner listing.
- Require shared transactions, versioned HMAC and independent runtime authorization.
- Enforce positive deadlines, finite admission, private diagnostics and safe shutdown.
