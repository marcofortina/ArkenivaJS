# Changelog

## 0.1.0

- Capture configured provider methods without executing callable metadata, and reject
  proxy providers and unbounded prototype traversal before authorization or storage work.
- Add scoped API key issuance, verification, atomic rotation/revocation and bounded owner listing.
- Require shared transactions, versioned HMAC and independent runtime authorization.
- Enforce positive deadlines, finite admission, private diagnostics and safe shutdown.
