<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# AMQP contracts and native field foundation

This increment supplies public AMQP types, the `AMQP_CAPABILITY` symbol and tested
internal field normalization through amqplib 2.2.0. The connection/plugin runtime,
publisher, consumers and real-broker acceptance remain under implementation.
There is no plugin factory or operational broker capability in this increment;
it must not be described as a working or production-ready RabbitMQ adapter.

The contract preserves explicit publisher confirms, mandatory-return outcomes,
single-use local acknowledgment submission, broker-specific consumer settings and
an `unknown` receipt when delivery cannot be established. These types do not
assert exactly-once delivery, business commitment or trusted wire tenant headers.

The required typed `AmqpConnectionConfig.topology` completes the trusted catalog
already required by the routing policy. It declares exchanges and their exact
approved publisher `routingKeys`, queues and bindings. The later runtime must
validate it before connection, check existing topology by default and provision
only with explicit `allowTopologyProvisioning: true`. Binding wildcard semantics
belong to RabbitMQ; no alternate routing implementation is introduced.

Internal capture already validates 1–8 uniquely named connections, up to 32
exchanges and queues and 128 bindings per connection, explicit resource names and
exact approved routing keys. A profile allows 1–1024 in-flight publications and
1 byte–16 MiB messages, with their product capped at 64 MiB. AMQPS secret URIs
require explicit credentials and reject query overrides, fragments and invalid
ports. The native heartbeat is 10 seconds and frame maximum is 128 KiB, matching
the supported RabbitMQ line's minimum frame size. Secret resolution and CA file
reads do not run during capture.

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
These offline tests do not replace the required future real RabbitMQ AMQPS,
confirm/return, ack/nack, restart, permission and multi-pod integration matrix.
