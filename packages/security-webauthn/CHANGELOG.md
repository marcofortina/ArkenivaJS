# Changelog

## Unreleased

- Verify native RSA and Ed25519 registration, self-attestation, assertions and
  one-use service evidence, including real PostgreSQL tenant authority and shared
  ceremony consumption through separate service instances.
- Add browser ceremony serialization types.
- Pin the private SimpleWebAuthn compatibility adapter with strict verification
  and bounded, sanitized input handling.
- Add internal trusted-authority, provider, rate-limit and test-clock boundaries
  for the versioned credential-store contracts; keep the factor factory private
  until its durable ceremony lifecycle is complete.
- Add private policy-bound, single-use ceremony claims and bounded browser JSON
  snapshots, with replay, ownership, expiry and hostile-input tests.
- Add private credential validation and versioned authentication/revocation
  transitions, including zero-counter races and fail-closed persistence checks.
- Delegate direct attestation to the pinned verifier and bound concurrent native
  verification work without an implicit queue.
- Expose the eight-operation factor service with live authority checks, stable
  account handles, versioned state and one-use evidence; keep production acceptance
  gated on durable-store, browser and performance verification.
- Add controlled Chromium/PostgreSQL acceptance through workspace and packed
  public artifacts, including signed counterless races across service processes.
