# Changelog

## Unreleased

- Add browser ceremony serialization types.
- Pin the private SimpleWebAuthn compatibility adapter with strict verification
  and bounded, sanitized input handling.
- Add internal trusted-authority, provider, rate-limit and test-clock boundaries
  for the versioned credential-store contracts; keep the factor factory private
  until its durable ceremony lifecycle is complete.
- Add private policy-bound, single-use ceremony claims and bounded browser JSON
  snapshots, with replay, ownership, expiry and hostile-input tests.
