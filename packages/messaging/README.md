# @arkenivajs/messaging

Optional Core NATS messaging through the explicitly selected `nats` SDK. Importing
this package opens no connection. Register `messagingPlugin` or explicitly await
`createNatsBus`; the core never installs this adapter automatically.

```ts
import { createApplication } from '@arkenivajs/core';
import { messagingPlugin } from '@arkenivajs/messaging';

const app = await createApplication({
  service: { name: 'orders', version: '1.0.0', environment: 'production' },
  plugins: [
    messagingPlugin({
      connectionStringEnv: 'NATS_URL',
      onError: async (failure, operation) => {
        // Await a bounded, application-owned error or dead-letter strategy.
        // Do not expose failure.message, payloads or internal causes publicly.
        await reportFailure(failure.kind, operation);
      },
    }),
  ],
});
await app.start();
try {
  const subscription = await app.messaging!.subscribe<{ orderId: string }>(
    'orders.created',
    async (message) => {
      // Validate the business DTO and authorize its origin before processing.
      await processOrder(message.payload.orderId);
    },
  );
  const receipt = await app.messaging!.publish(
    'orders.created',
    { orderId: '42' },
    {
      correlationId: 'request-42',
    },
  );
  console.log(receipt.acknowledged); // false for Core NATS
  await subscription.close();
} finally {
  await app.stop();
}
```

This integration fragment requires the application's `reportFailure` and
`processOrder` implementations. The error strategy is mandatory, asynchronous
and receives an abort signal with a one-second budget. A rejected, synchronous
or overdue strategy makes the owner unhealthy and starts cleanup. Raw causes
are private developer diagnostics. See the disposable fixture for secure
configuration and the [complete consumer example](../../examples/messaging/README.md) for executable application code.

Error strategies retain their captured callback and receiver without evaluating
callable `bind`, `name` or `length` properties. Later callback replacement does
not change the captured strategy. Policy method lookup rejects accessors and
proxies and is bounded to 32 prototype levels before any connection is opened.

## Connection and authority

`NATS_URL` is a private environment value resolved at explicit startup. Use
`tls://USER:PASSWORD@HOST:PORT/?prefix=ACCOUNT.&caFile=/private/ca.pem&certFile=/private/client.pem&keyFile=/private/client.key`
with URL-encoded credentials and query values. The port, scoped credentials and
literal namespace ending with a dot are required. Only `prefix`, `caFile`,
`certFile`, `keyFile` are supported query keys; duplicate and unknown keys fail.
Certificate/key must be paired. PEM paths are absolute bounded regular files;
private keys require owner-only permissions. TLS-first handshakes verify server
identity and roots; the optional client pair enables mTLS. Without `caFile`,
Node's captured public roots apply. Global TLS verification bypass and a process
minimum below TLS 1.2 are rejected. No plaintext fallback or cluster-discovered
server override exists. Rotate credentials/certificates with a controlled owner
restart.

A namespace organizes subjects; the broker account and server ACL enforce
publisher/subscriber authority. Logical topics are literal ASCII tokens joined
by dots, at most 256 characters. Wildcards and whitespace are rejected. The
namespace is at most 128 characters. Authenticated transport alone does not
authorize a payload's tenant. Consumers must independently verify publisher
identity and scoped business authorization. Wire envelopes never construct
`VerifiedTenantContext`; a wire-level `tenant` field is rejected. A business
payload field named `tenant` remains ordinary untrusted data.

## JSON and delivery

The schema-version-1 envelope contains a UUIDv4 `messageId`, logical topic,
checked JSON payload and optional safe ASCII correlation ID (128 characters).
Unknown envelope fields, invalid UTF-8 and unsafe prototype properties fail.
Payload capture occurs before asynchronous submission; later caller mutation
cannot alter the sent body. Incoming JSON is frozen before the handler runs.
Generic `T` does not validate an application's business DTO.

Supported values are finite JSON numbers, strings, booleans, null, dense arrays
and plain records. Accessors, custom classes/serializers, undefined, bigint,
symbols, cycles and unsafe prototype keys fail. Limits are 64 levels, 50,000
nodes, 10,000 items/properties and a 1 MiB encoded envelope, also bounded by the
broker's actual maximum payload. Cumulative traversal bytes are checked before
cloning; final UTF-8 encoding is checked separately.

This module implements **Core NATS**, with no JetStream, durability, consumer
ack/nack, redelivery or exactly-once promise. `publish` sends once and waits for
a native flush/PONG communication barrier. Its receipt always has
`acknowledged:false`: a PONG does not prove subscriber acceptance or persistence.
A disconnect rejects new work rather than buffering publications for later
replay. Native reconnect restores subscriptions and permits future operations;
the adapter never replays an uncertain publication. The selected policy allows
five reconnect attempts with 200ms delay and up to 100ms jitter, and a one-second
heartbeat with two outstanding pings. There is no automatic initial-connect retry.

## Budgets, backpressure and lifecycle

Operations accept positive safe-integer `timeoutMs` and `AbortSignal`, default
5,000ms. Once submitted, interrupted publications report
`details.outcome='unknown'`; reconcile business effects before any retry.
Reservations remain held until the actual native work settles, even after a
caller timeout. Delayed diagnostics cannot submit expired work. Admission is
bounded to 64 pending operations, 32 subscriptions, 128 queued messages and
8 MiB combined retained publication/receive bodies. Each subscription processes
one message at a time with a five-second handler deadline. Overload fails the
owner, reports a visible `overflow` and counts discarded bodies; no unbounded
queue or silent drop policy is installed.

`subscribe` resolves after native registration/flush. Its signal also controls
subscription lifetime. `Subscription.close()` unregisters and drains owned work;
it is idempotent. A handler must not await its own subscription/bus closure:
this rejects with `EK_LIFECYCLE_STATE` to prevent self-deadlock. It may signal
lifetime cancellation. Handler errors reach the configured policy once, without
redelivery. Uncooperative handler promises remain observed and owned after a
logical deadline; JavaScript cannot forcibly stop arbitrary application code.

A managed standalone bus adds `health(options?)`, `stats()` and
`close(options?)`. Health performs an actual flush. Close stops admission,
unregisters subscriptions and drains the transport within five seconds,
then attempts forced native closure within one additional second. Caller or
application cancellation forces closure. Incomplete cleanup rejects with typed
`details.cleanupFailed=true`; failures are not reported as clean shutdown.
A closed owner cannot restart. Plugin instances are reusable across independent
applications. Their frozen facade rejects before READY and after closure;
startup performs a native health probe before global activation.

Common failures are `EK_CONFIG_INVALID`, `EK_CONFIG_MISSING`, `EK_ABORTED`,
`EK_TIMEOUT`, `EK_BACKEND_UNAVAILABLE`, `EK_LIFECYCLE_STATE` and
`EK_RESOURCE_CLOSED`. Internal causes remain private. Numeric `stats()` expose
connectivity, subscription count, pending publications, retained bytes,
queued/active work, successes, faults, drops and observer failures. These are
process observations, not durable delivery receipts.

## Observability and tenant accounting

`messaging.publish`, `.subscribe`, `.health` and `.process` spans preserve
application outcomes under diagnostic failures. Corresponding `.duration`
histograms use seconds and explicit shared buckets. Default observations carry
no topic, message ID, payload, credentials or tenant metric labels. Processing
CPU/RAM remains process-level.

A managed meter records actual publication attempts, elapsed milliseconds and
encoded application-envelope bytes in the current verified session using
`messaging.publish`, `messaging.client.elapsed`, `messaging.payload.bytes`.
TLS/network bytes are unavailable and mark `driver_bytes_unavailable`; no
fabricated billed egress or server execution time is reported. Metering works
with tracing off. Consumers and error policies detach request accounting scope;
start a separate explicitly authenticated `meter.measure` operation for
background work. Payload tenant fields do not establish that authority.

The plugin discovers declared logging/telemetry/meter owners through explicit
dependency edges; standalone callers inject their own ports. An injected meter
must support the managed background scope controls. Diagnostic failure does not
replay business work.

## Compatibility and verification

The specified SDK is `nats` 2.29.3, Apache-2.0, with `nkeys.js` 1.1.0
(Apache-2.0) and `tweetnacl` 1.0.3 (Unlicense). Upstream moved the package to
`@nats-io/transport-node`; this adapter retains the specified implementation.
See the [declaration-only strict TypeScript correction](compat/README.md) and
[third-party notices](THIRD_PARTY_NOTICES.md). No runtime SDK source is changed.
The portable public entry point exposes no native SDK implementation types.

Live tests use the [private disposable NATS fixture](test/fixtures/README.md)
in an isolated VM or ephemeral CI runner. They require explicit opt-in and fail
when absent. Real TLS/authentication failures, malformed/spoofed envelopes,
handler failures, lost-PONG uncertainty, reconnection without replay and cleanup
are tested. Signed JWT identities plus persisted JSONL events verify independent
publisher/consumer accounting with tracing disabled. Unit fault injection covers
bounded queues and native cleanup faults; it does not replace the live broker gate.

Run `pnpm --filter @arkenivajs/messaging coverage` using the fixture's private
environment. The suite enforces 95% line and branch coverage.

| SDK         | Server                                              | Node                        | Platform                            | Verified date |
| ----------- | --------------------------------------------------- | --------------------------- | ----------------------------------- | ------------- |
| nats 2.29.3 | NATS 2.15.1; TLS-first, mTLS and scoped credentials | 22.23.4 / 24.22.1 / 26.12.1 | Linux x64; Ubuntu 24.04 QEMU server | 2026-10-25    |
