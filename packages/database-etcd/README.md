# @arkenivajs/database-etcd

Optional key-value support using the actual **etcd3 1.1.2** SDK. Import and
application creation open no socket. Startup captures one explicit database
definition and authenticates a scoped keys-only read before activating `app.etcd`.
The provider never routes through SQL.

```ts
import { createApplication } from '@arkenivajs/core';
import { etcdPlugin } from '@arkenivajs/database-etcd';

const app = await createApplication({
  service: { name: 'configuration-reader', version: '1.0.0', environment: 'production' },
  plugins: [etcdPlugin()],
  databases: { configuration: { driver: 'etcd', connectionStringEnv: 'ETCD_URL' } },
});
await app.start();
try {
  await app.etcd!.put('service:mode', new TextEncoder().encode('enabled'));
  const value = await app.etcd!.get('service:mode');
  console.log(value && new TextDecoder('utf-8', { fatal: true }).decode(value.value));
} finally {
  await app.stop();
}
```

## Configuration and authorization

`ETCD_URL` is an explicit URL such as
`https://etcd.example:2379?sslca=/private/ca.crt&sslcert=/private/client.crt&sslkey=/private/client.key&prefix=/tenant-a/`.
Percent-encode query values. The only query fields are `sslca`, `sslcert`,
`sslkey` and `prefix`; duplicates, URL credentials, paths, fragments and unknown
fields reject. SQL pool options are unsupported. An optional `endpoints` array
contains 1–8 plain origins with the same protocol; its first origin must match
the configured URL. Origins without an explicit port use HTTP/HTTPS defaults;
specify port 2379 for ordinary etcd endpoints.

Production and remote connections require HTTPS and paired client certificate
and key. The client verifies server certificates and DNS/IP identity with TLS
1.2 minimum. `sslca` is an optional explicit CA bundle; otherwise system trust
roots are captured. Each TLS file must be absolute, regular, nonempty and at
most 1 MiB. Material is captured at startup; reconstruction is required to rotate
it. There is no insecure certificate override or username/password URL profile.
For explicitly trusted local development/test only, an endpoints-only definition
such as `{ driver: 'etcd', endpoints: ['http://127.0.0.1:2379'] }` permits plaintext
loopback without an identity. Never expose that profile on a shared network.

The namespace is empty or an absolute ASCII prefix ending in `/`, at most 256
bytes. Letters, digits, `/`, colon, underscore and hyphen are permitted.
The adapter prepends it to portable keys and removes it from watch event keys.
A prefix organizes data; **etcd server roles enforce isolation**. Enable etcd
authentication, bind each client certificate common name to a least-privileged
user and grant that user access only to its approved prefix. A native client
retains its server account's authority. Do not trust a namespace taken from
unverified request data. The fixture root identity is solely for provisioning
and destructive compaction tests.

## Portable operations

| Operation                                                    | Result                                                                                                                     |
| ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| `get(key, options?)`                                         | `EtcdValue` or `null`; exact raw bytes, `revision` and `version` as bigint.                                                |
| `put(key, bytes, { leaseId?, ...options }?)`                 | Acknowledged completion; accepts only a currently valid lease owned by this provider.                                      |
| `delete(key, options?)`                                      | Actual boolean deletion acknowledgment.                                                                                    |
| `compareAndSwap({ key, expectedRevision, value }, options?)` | Actual boolean transaction result; expected revision is an exact nonnegative int64 bigint. Zero means absent.              |
| `watch(prefix, options?)`                                    | Closable async iterator of ordered put/delete events with bigint revisions. Empty prefix watches the configured namespace. |
| `grantLease(ttlSeconds, options?)`                           | Frozen handle with string `id`, explicit `keepAlive(): void` and idempotent asynchronous `revoke(options?)`.               |

Portable keys are nonempty valid UTF-8, at most 4,096 bytes before the namespace,
without NUL/CR/LF. Raw `Uint8Array` inputs are copied before asynchronous work;
values are bounded to 1 MiB. Reads reject oversized stored values rather than
truncating them. The native message budget is 2 MiB. Conversion to text or JSON
belongs to the application: use an explicit fatal UTF-8 decoder and serialize
bigint metadata as decimal strings. Arbitrary binary data remains binary.

CAS uses the native atomic transaction and exact decimal revision strings. It
never rounds through a JavaScript number, invokes a transaction callback or
replays a failed mutation. See the [executable consumer](../../examples/etcd/README.md).

## Watch recovery and lease ownership

Each watch owns a separate actual SDK client. The implementation uses the
selected SDK's exported watch RPC and protobuf conversion to retain exact int64
resume cursors. It does not use the high-level watch builder's numeric cursor
conversion or implement a custom gRPC driver. The SDK release is pinned because
these exported RPC interfaces are marked internal by its authors.

On a transient disconnect, resubscription begins at the next fully processed
revision. A resumed creation acknowledgment cannot advance beyond unread replay;
fragmented revisions remain eligible for replay until their final fragment.
Replay can contain duplicates. Consumers requiring deduplication should retain
revision/key/type identity. The queue is bounded to 256 events and 2 MiB. Overflow
or compacted history terminates with `EK_KV_CONFLICT` and `details.watchGap=true`;
compaction includes an exact decimal `compactedRevision`. Rebuild an authorized
snapshot before opening a new watch. No event is silently discarded as success.
The iterator supports one pending `next()`. Close it in `finally`; breaking a
`for await` loop also invokes iterator return and cleanup.

Granting a lease does not renew it automatically. Only calling `keepAlive()`
starts renewal; repeated calls share the same loop. An observed expiry or
permanent authorization failure stops renewal and invalidates new attachments.
The adapter never grants a replacement lease silently. A randomly chosen positive
int64 identity is known before submission, so an unacknowledged grant can still
be cleaned up by that identity. An explicit rejected duplicate grant never
revokes another owner's existing lease. Shutdown stops renewal and revokes owned
or provisional grants, with separately budgeted cleanup even after caller abort.

## Budgets, shutdown and diagnostics

Calls accept a positive safe integer `timeoutMs` and `AbortSignal`. The monotonic
operation budget defaults to 15 seconds, readiness to 5 seconds, per-resource
cleanup to 5 seconds and connection shutdown to 20 seconds. Watch progress is
requested every 5 seconds; silent streams and reconnect recovery are bounded to
15 seconds, with 100–1,000 ms reconnect delays. A setup budget does not expire an
already opened watch; caller cancellation still governs its lifetime.

Admission is bounded independently to 128 pending portable attempts, 64 watches
and 64 leases per connection. No application command is automatically replayed.
Native global/host retry policies and gRPC automatic retries are disabled.
Only idempotent watch resubscription, existing-lease heartbeats and explicit
owned cleanup perform recovery. Call cancellation is isolated from unrelated
in-flight operations; resource streams own separate SDK clients.

A submitted write interrupted before acknowledgment reports
`details.outcome='unknown'` and `retryable=false`. Reconcile application state
before deciding whether another write is safe. Explicit server rejection retains
its acknowledged failure. Cleanup failures are surfaced with private aggregate
causes and, for failed lease acquisition cleanup, the requested `leaseId`.
Retained provider facades reject after application closure.

Each submitted portable attempt records one `db.query`. Optional framework CLIENT
spans use bounded system/operation names; OTel duration is seconds and managed
meter elapsed usage is milliseconds. No server CPU, I/O, wire bytes or native
channel counts are invented. Quality marks `driver_bytes_unavailable`; obtaining
a native handle inside a managed scope marks `not_instrumented`. Diagnostic
failures cannot replay work or replace an acknowledged native result. Keys,
values, credentials and raw server text are absent from default diagnostics;
original exceptions remain private causes for explicit developer inspection.

`native()` returns the actual `Etcd3` instance. Native operations bypass portable
prefixing, bounds, deadlines, conversion and instrumentation. The application
owns this instance; do not close it independently. Explicitly created SDK clients
and streams remain the caller's cleanup responsibility. Avoid duplicate host
auto-instrumentation unless its collection and redaction policy is reviewed.

## Verification

The [private mTLS fixture](test/fixtures/README.md) runs only inside a dedicated VM
or disposable CI runner. Missing live configuration fails rather than skipping
tests. Compaction tests are destructive to the fixture's history: serialize local
Node-version runs and never share this fixture with an application or another job.

Local verification on 2026-10-25 used etcd **3.7.3**, Linux x86-64 in QEMU and
Node **22.23.4 / 24.22.1 / 26.12.1**: 99 unit/contract/live cases per runtime,
98.08% line coverage and at least 96.18% branch coverage, enforcing 95% for each.
This covers mTLS/ACL isolation, binary values, concurrent CAS, exact cursors,
replay/compaction, lease loss/cleanup, isolated cancellation and unknown write
outcomes. Other platforms, server versions, multi-member failover and etcd 3.7
RangeStream are not qualified by this matrix. See [third-party notices](THIRD_PARTY_NOTICES.md)
for the selected SDK and its upstream license attributions.

With an optional health collector installed, the plugin performs a fresh
readonly native readiness probe through its owned client and bounded operation
scope. Health runs after owner initialization, before inbound listeners activate;
public provider facades still require application READY. Scoped hook integration
tests use the actual authenticated disposable server and reject stale callbacks
and pre-aborted operations. Health never closes the native owner's client.
