# NATS declaration compatibility

`nats-exact-optional.diff` corrects two optional declarations in `nats@2.29.3`:
`Msg.headers` and `NatsConnection.info` explicitly permit undefined, matching
their upstream runtime getters. The modified declaration carries a prominent
notice. No JavaScript, protocol, cryptography or transport implementation changes.

The workspace applies this exact-version correction through pnpm's hash-checked
`patchedDependencies`. TypeScript retains strict checks, including
`exactOptionalPropertyTypes` and `skipLibCheck: false`. The portable messaging
entry point does not expose native SDK types. Preserve the upstream Apache-2.0
license and attribution when distributing the corrected dependency.

The specified `nats` package has moved upstream to `@nats-io/transport-node`.
This module retains the specified package; switching implementations requires
an explicit compatibility and dependency review.
