# Changelog

## 0.1.0

- Add optional GraphQL contracts and administrative capability identity.
- Pin the selected Mercurius and GraphQL engines without changing REST-only dependencies.
- Validate immutable startup declarations, finite budgets and schema field mappings before transport registration.
- Bind guarded queries and mutations to the existing listener, with verified identities, field authorization, finite execution limits and safe errors.
- Add bounded native request loaders, opaque parent correlation, isolated caches and serial mutation invalidation, verified against actual PostgreSQL query counts.
- Protect upstream metadata fields with per-request field policy and explicitly scoped administrative introspection while preserving unrelated native schemas.
- Enforce result byte limits during standard JSON encoding and recheck the total operation deadline before sending.
- Add a development/test-only authenticated GraphiQL IDE with local workers, disabled persistent storage and preserved bundled dependency notices.
- Verify shared secure HTTP/2 queries and mutations, HTTP/1.1 fallback, tenant isolation, stream cancellation and graceful listener drain.
- Verify physical admission at 128 concurrent operations and preserve actual mutation ownership through forced shutdown.
- Export normalized operation, complexity, loader and denial metrics through the existing telemetry provider, with detailed field timing and no duplicated HTTP byte measurements.
- Preserve W3C HTTP trace parents and attach normalized GraphQL child spans without replaying business work when diagnostic context fails.
- Attach verified tenant usage to one HTTP parent and an owned GraphQL child, with exact parent bytes, successful field counts and actual loader items.
- Preserve the timeout status during late upstream error formatting and report physically unfinished work with incomplete or unknown usage outcomes.
- Bound IDE manifest and asset reads before allocation, reject links/nonregular files and validate aggregate bytes before loading another asset.
- Preserve revocable server-owned execution bindings across native context copies; verify the pinned subscription engine with authenticated WSS clients while framework subscriptions remain disabled.
- Share bounded operation-envelope checks across transports and preflight native subscription ASTs with runtime identity provenance, transport restrictions and variable-driven budgets.
- Filter standard WebSocket client frames before the native iterator receives them, with bounded text/control inputs, explicit authentication payload shape and safe closure on admission failure.
- Reserve subscription operations and pending native frames before dispatch, require authenticated ACK ordering and retain capacity until physical retirement while ignoring benign completion races.
- Retain physical source ownership through late acquisition, cancellation and pending reads; release native WSS streams exactly once and observe provider cleanup failures.
- Reauthorize each subscription event with fresh operation scopes, guard source allocation and per-event default/metadata fields, and retain late timed-out sources through physical cleanup.
- Materialize bounded subscription responses once before native WebSocket serialization, preserve safe native GraphQLError compatibility and prevent private error details or oversized partial results from reaching clients.
- Share the native WebSocket dispatcher with realtime on the existing Fastify listener, preserving independent route limits and both module initialization orders.
- Bound native subscription writes by queued messages, buffered bytes and physical callback deadlines; sanitize start errors and prevent late callbacks from acknowledging abandoned connections.
- Own authenticated native subscription connections through periodic tenant revalidation, per-operation cancellation and late source retirement; release idle execution capacity and preserve long configured deadlines without timer overflow.
- Enforce shared-listener WSS admission and global connection capacity, retain physically pending shutdown work and quarantine provider retirement failures before accepting more clients.
