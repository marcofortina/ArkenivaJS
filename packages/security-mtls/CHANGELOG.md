# Changelog

## 0.1.0

- Verify native mutual TLS without optional ALPN, DNS/IP peer policy, altered CA
  snapshots, certificate-chain boundaries and final conversion size limits.
- Capture credential and trust callbacks without evaluating callable metadata,
  retaining original receivers and rejecting proxies and unbounded classification traversal.
- Add explicit credential profiles, complete startup snapshots and atomic explicit reload.
- Provide validated Node-compatible TLS client/server converters with strict runtime provenance.
- Verify peer certificate policy asynchronously through an independent chain and revocation authority.
- Exercise real mutual TLS, native ALPN/SNI, CRL denial, provider failures and rotation rollback.
