# Core NATS messaging consumer

This executable project uses built public packages, a randomly owned subject
and an explicitly disposable authenticated NATS endpoint. It publishes one
valid order and one invalid business DTO, verifies correlation, observes the
configured asynchronous handler error strategy and closes the subscription
and application. `acknowledged:false` is deliberate: Core NATS flush does not
confirm durable delivery or consumer acceptance.

Prerequisites: supported Node 22/24/26, frozen pnpm installation, built workspace
and the [private NATS TLS fixture](../../packages/messaging/test/fixtures/README.md).
Run fixture containers in a dedicated VM or ephemeral CI runner. Keep its
private environment and certificates outside the checkout; never paste URLs
into logs. Use its environment loader to execute:

```sh
pnpm install --frozen-lockfile
pnpm build
python3 packages/messaging/test/fixtures/run.py /private/runtime/nats-fixture/environment.json pnpm --filter @arkenivajs/example-messaging start
python3 packages/messaging/test/fixtures/run.py /private/runtime/nats-fixture/environment.json pnpm --filter @arkenivajs/example-messaging test:integration
```

Expected final JSON:

```json
{ "acknowledged": false, "received": 1, "correlated": true, "handlerFailures": 1 }
```

`orderDTO` validates the business shape separately from the bus envelope and
projects only public fields. The in-memory failure array is a bounded demo
observation for these two messages, not a production dead-letter store. An
application must supply its own bounded asynchronous error policy. A payload
field or remote trace does not authenticate a tenant; independently authorize
publisher and tenant before starting a background metering operation.

Missing disposable opt-in rejects with `EK_CONFIG_INVALID`; absent URL uses
`EK_CONFIG_MISSING`. TLS/authentication errors stop startup, without insecure
fallback. Timeout after publication can have an unknown business effect and
must not trigger blind replay. The CLI prints sanitized error JSON without
credentials, causes or stack traces. Unit tests verify DTO projection and safe
CLI failures. Integration tests execute both the exported workflow and actual
CLI process against the real broker and require clean termination.

Stop the owned fixture using its documented Compose command. This example
creates no durable stream, consumer or broker storage and leaves no subscription
running after application shutdown. See the [adapter reference](../../packages/messaging/README.md)
for queue bounds, lifecycle, measured bytes and native reconnect semantics.
