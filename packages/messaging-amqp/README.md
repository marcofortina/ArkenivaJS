<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native AMQPS adapter

`amqpPlugin(settings)` installs the optional `AMQP_CAPABILITY` through amqplib
2.2.0. Startup resolves external connection secrets, verifies AMQPS peers and
checks the trusted topology before making the service available. Importing the
package or constructing the plugin does not resolve secrets or open connections.
The [executable application](../../examples/amqp/README.md) includes native
diagnostics and independent public package installation. Performance campaigns
and final release acceptance remain separate from these functional tests.

The contract preserves explicit publisher confirms, mandatory-return outcomes,
single-use local acknowledgment submission, broker-specific consumer settings and
an `unknown` receipt when delivery cannot be established. These types do not
assert exactly-once delivery, business commitment or trusted wire tenant headers.

The required typed `AmqpConnectionConfig.topology` completes the trusted catalog
already required by the routing policy. It declares exchanges and their exact
approved publisher `routingKeys`, queues and bindings. The runtime validates it
before connection, checks existing topology by default and provisions only with
explicit `allowTopologyProvisioning: true`. Broker permissions remain authoritative;
this option does not grant configure rights. Binding wildcard semantics
belong to RabbitMQ; no alternate routing implementation is introduced.

Internal capture already validates 1–8 uniquely named connections, up to 32
exchanges and queues and 128 bindings per connection, explicit resource names and
exact approved routing keys. A profile allows 1–1024 in-flight publications and
1 byte–16 MiB messages, with their product capped at 64 MiB. AMQPS secret URIs
require explicit credentials and reject query overrides, fragments and invalid
ports. The native heartbeat is 10 seconds and frame maximum is 128 KiB, matching
the supported RabbitMQ line's minimum frame size. Secret resolution and CA file
reads do not run during capture.

## Delivery and ownership

Publishers use a native confirm channel. A `confirmed` receipt acknowledges the
broker confirm, while a correlated mandatory return produces `unroutable` even
when concurrent messages share an application message ID. Cancellation, deadline
or disconnection after submission can produce `unknown`. Recovery never republishes
such messages. Native write backpressure stops new admission until `drain`; each
profile also has an explicit concurrent publication bound, with no waiting queue.
The native producer channel uses a write high-water mark of 16 frames.

Consumers use native per-channel prefetch and manual acknowledgments. Each
delivery permits one local `ack()` or `nack({ requeue })` submission; it does not
claim broker-side transactional acknowledgment. A handler failure rejects without
requeue unless its trusted subscription explicitly selects `requeue`. Dead-letter
exchanges and bounded retry policy belong to the broker configuration. Wire tenant
headers never populate `verifiedTenant` or establish authorization.

The native frame assembly boundary rejects oversized content before retaining
the whole body. Header-policy and size violations stop that profile instead of
reconnecting indefinitely into the same poison delivery. A native reconnect has
eight bounded attempts and restores consumer channels without migrating old
acknowledgments or duplicating active handlers. Each profile permits at most
eight subscriptions; aggregate prefetch body budgets cannot exceed 64 MiB.
Local running handlers are bounded by prefetch even when they acknowledge early;
at most one further prefetch window can wait unacknowledged on that channel.

Shutdown stops new admission, cancels consumers, drains active handlers and closes
owned connections. A deadline closes transport and returns an explicit error;
already running handlers or uncooperative secret providers remain owned until
they actually settle. A subsequent close may observe completed cleanup.
Operation cancellation captures a native signal before admission. Later caller
hook replacement cannot change success or abort cleanup; proxy controls, shadowed
signal hooks and prototype traversal beyond 64 levels fail with
`EK_CONFIG_INVALID` before native work begins.
`native(name)` returns the actual approved SDK model as `unknown` for trusted
application integrations, whose native operations require explicit instrumentation.
Built-in diagnostics contain only fixed operation/outcome labels and numeric
measurements, excluding connection URIs, secrets, resource names and message data.

## Native field fidelity

The internal adapter accepts strings, finite numbers, booleans, null, signed
64-bit bigint, whole-second nonnegative Date values, independent binary bytes,
arrays and tables. It rejects unsafe integer numbers, bigint overflow, invalid or
subsecond dates, unsupported native decimals, undefined, accessors, shared-memory
bytes, cycles, sparse arrays and dangerous/reserved table keys. JavaScript native
type-override objects containing `!` are not accepted as application tables.

Limits are 128 cumulative table entries, 16 KiB of actual native encoded table
bytes, four nested container levels and 256 items per array. Inputs are copied
before native encoding and delivery fields are copied before exposing them.
Readonly object/array snapshots do not make Date setters or owned byte arrays
intrinsically immutable; mutations cannot alter caller/driver-owned values.

The pinned native codec performs serialization and exact size measurement. Its
documented int64/timestamp wrappers carry the public values; no AMQP serializer is
reimplemented. AMQP timestamps have whole-second precision: unsupported
milliseconds are explicitly rejected instead of rounded. See the
[RabbitMQ conversion reference](https://www.rabbitmq.com/docs/conversions).

A scoped upstream correction retains bigint outside the safe-number range and
decodes tables without prototypes. Safe native numeric results remain numbers,
including a safely representable AMQP int64 initially supplied as bigint. This
preserves the AMQP numeric value; JavaScript constructor identity is not carried
by an AMQP integer. See [third-party notices](THIRD_PARTY_NOTICES.md) and the
[upstream native source](https://github.com/amqp-node/amqplib/tree/v2.2.0).

Independent installations must apply the exact packaged compatibility diff before
using the runtime. Copy `package/compat/amqplib-native-field-fidelity.diff` from the
reviewed package archive into the application's `compat/` directory and configure:

```yaml
patchedDependencies:
  amqplib@2.2.0: compat/amqplib-native-field-fidelity.diff
```

The development workspace already applies this exact pin. Normalization and
configuration capture fail `EK_AMQP_CONFIG` if a native fidelity probe detects an
unpatched installation. The external artifact verifier copies only byte-matching
diffs from actual packed archives and applies those present in its resolved
dependency graph. It never silently falls back to lossy decoding.

## Verification

Run `pnpm --filter @arkenivajs/messaging-amqp build`, `typecheck`, `lint` and
`test:unit`. Native codec roundtrips cover both int64 boundaries, timestamps,
binary values, negative zero, nested values and the exact 16 KiB boundary.
Negative tests prove explicit rejection without a connection or publication.
`test:integration` requires `ARKENIVA_AMQP_FIXTURE` pointing to private metadata for
an explicitly owned disposable AMQPS broker. Real-broker cases cover native
confirms, correlated returns, single-use ack/nack, explicit requeue, handler failure,
TLS rejection, least privilege, size rejection, transport recovery and redelivery
between two application instances, broker restart, actual channel close, native
write backpressure and externally configured dead-letter routing. Private metadata and broker credentials must
remain outside the repository. Local runs use the owned integration VM.
