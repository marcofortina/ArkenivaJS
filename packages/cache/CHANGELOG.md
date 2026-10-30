# Changelog

## 0.1.0

- Capture tenant verification with its original receiver without executing binding metadata, accessors or proxy traps; accept only boolean true as verification evidence.

- Add an optional Redis-backed JSON cache with checked versioned envelopes and safe finite default expiration.
- Bind tenant cache facades to actual verifier-owned contexts, with distinct namespaces and explicit cross-tenant key rejection.
- Preserve actual backend acceptance, deletion counts and uncertain effects across bounded cancellation, shutdown and observation failures.
- Verify live TLS Redis, signed JWT provenance and independent tenant metering with tracing disabled on supported Node versions.
