# Changelog

## 0.1.0

- Add bounded native PEM/DER metadata and fingerprint utilities.
- Register an application-owned X.509 capability with explicit configured CA sets and a trusted chain/revocation provider.
- Fail closed on incomplete chains, time or hostname mismatch, provider outage, cancellation and shutdown.
- Verify native TLS and real CRL rejection with ephemeral certificates and independent lifecycle tests.
