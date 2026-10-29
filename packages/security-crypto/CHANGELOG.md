# Changelog

## 0.1.0

- Capture external key methods without evaluating callable metadata; retain the
  original receiver and reject proxy providers and unbounded classification traversal.
- Add explicit capability registration, typed external secret providers and bounded native cryptographic operations.
- Bind versioned AES-256-GCM envelopes to metadata and caller AAD, with strict key rotation and safe failures.
- Support HMAC-SHA256, Ed25519 and P-256 without implicit algorithm fallback or unbounded operation queues.
