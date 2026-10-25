# Changelog

## Unreleased

- Add explicit runtime subject/management authorization, versioned external HMAC-SHA256 keys and environment/test-clock contracts with fail-closed guards.
- Add shared TOTP lifecycle and durable storage type contracts.
- Pin and test the private upstream RFC 6238/provisioning compatibility adapter.
- Implement the public factor lifecycle with independent authority checks, shared attempt limits, atomic replay/recovery transitions, secret-bearing provisioning and durable single-use evidence.
