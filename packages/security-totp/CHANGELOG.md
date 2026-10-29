# Changelog

## Unreleased

- Reject executable operation options and fabricated or shadowed cancellation signals
  before authority/storage work, using the shared native signal capture guard.
- Capture provider methods without invoking custom function metadata and reject
  Proxy configuration, provider prototypes and callable wrappers before reflection.
- Add explicit runtime subject/management authorization, versioned external HMAC-SHA256 keys and environment/test-clock contracts with fail-closed guards.
- Add shared TOTP lifecycle and durable storage type contracts.
- Pin and test the private upstream RFC 6238/provisioning compatibility adapter.
- Implement the public factor lifecycle with independent authority checks, shared attempt limits, atomic replay/recovery transitions, secret-bearing provisioning and durable single-use evidence.

- Align factory inputs with the independent per-operation subject authority and
  opaque recovery HMAC backend; default to production and restrict clocks to tests.
- Bind recovery verifiers to active factors, validate bounded rotation candidates
  and support ten through twenty independent recovery codes.
- Apply the shared attempt budget to enabled-state reads before factor access.
