<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native socket interoperability verification

Build the workspace, make OpenSSL available and choose a fresh absolute external
report directory:

```sh
pnpm --filter @arkenivajs/benchmark-foundation socket --verify /private/socket-verification
ARKENIVA_SOCKET_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation socket --smoke /private/socket-smoke
ARKENIVA_SOCKET_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation socket --smoke-unix /private/socket-unix-smoke
ARKENIVA_SOCKET_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation socket --smoke-tls /private/socket-tls-smoke
```

Four isolated server profiles compare native Node `net`, `tls` and `dgram` with
the actual socket service, including standard/detailed SDK profiles. Each scenario
uses an independent native client process. TCP echoes 64 bytes and 64 KiB, TLS
echoes 64 bytes, UDP echoes 256 bytes and the Unix socket echoes 4 KiB. Stream
chunks remain arbitrary bytes, with no invented framing protocol.

Clients verify complete byte identity. Server counters independently verify actual
application bytes received and accepted by outbound writes. Stream acceptance
counts include the TLS connection rejected for its wrong hostname. Actual client
TLS protocol and cipher are recorded. An ephemeral P-256 test certificate and key
live in a private temporary directory; the key is restricted to its owner. Trust
is supplied only to the owned TLS client. No system trust setting changes.

Every listener closes before its result is accepted. The Unix socket path must be
absent after shutdown. The parent removes its private temporary directory after
all workers exit. SDK payloads and structured reports must exclude application
bytes, endpoints and credential-file paths. Negative tests also reject foreign
destinations and actual corrupted echoes.

This bounded functional check retains `releaseGate: false`. It proves only the
observed local UDP request/reply, without a UDP delivery guarantee or network-loss
claim. The direct native baseline omits framework admission, queue bounds,
cancellation and lifecycle policy. Unmarked `--smoke` rejects before certificate
or report allocation. Explicit disposable sampling retains the five original
verification scenarios and then starts a distinct TCP listener with independent
counters. Its single measured scenario uses a fresh independent native client
process for each 64-byte echo: exactly 20 warmup callbacks and 100 retained
Tinybench samples in each profile. No client or connection pool is reused.

Every callback includes client process startup, IPC, TCP connect, complete byte
comparison and physical process exit. The client also observes first incoming
byte and exchange completion from just after native socket construction. Those
inner observations exclude process startup and IPC and are reported separately;
Tinybench latency is the complete client lifecycle, not steady-connection latency.
At most 120 bounded metadata results are retained, within a ceiling of 128; no
payload, marker or destination is retained in the report. Completion rejects
incomplete evidence or concurrent callbacks, then independently requires 120
accepted connections and exactly 7,680 bytes received and sent by the distinct
server listener. That listener must close before successful completion.

Linux process-tree supervision includes the server worker and all actual client
descendants, including verification clients, startup, warmup, sampling, export
and cleanup. Every owned process must be waited, with no remaining descendants
and no inaccessible or truncated resource observations. CPU is aggregate for
that lifecycle. Sampled summed RSS can count shared pages repeatedly and miss
brief peaks; it is neither exact peak memory nor PSS. Kernel socket buffer bytes
remain unknown. TLS and UDP remain functional verification in these original modes;
the explicit TLS mode below adds one bounded measured scope. No handshake-rate
or backpressure campaign is claimed. Dedicated-runner budgets, calibrated policy-equivalent overhead, five
paired repetitions and one-hour soak acceptance remain separate work.

`--smoke-unix` selects a separate Linux Unix-stream **4 KiB** lifecycle scope,
matching the R6 workload. The existing `--smoke` remains TCP **64 bytes**; neither
number denotes a concurrent client count. Both modes retain the same five
untimed verification scenarios and use concurrency one. Unix sampling creates a
distinct listener and starts 120 independent client processes: 20 warmups and
100 measured lifecycles. Each client verifies all 4096 echoed bytes, and the
listener independently reports 120 accepted connections and exactly **491,520
application bytes in each direction**. The 100 measured callbacks account for
409,600 bytes per direction and the 20 warmups for 81,920 bytes; these portions
are derived from the fixed payload and checked callback counts. Listener totals
and each independent client's completed echo are observed directly.

Unix verification is kept separate from sampling: the five original scenarios
use six waited client processes, including the deliberately rejected TLS
hostname. Their listeners independently report five accepted stream connections
and 70,016 application bytes in each direction; UDP contributes one observed
request/reply rather than a stream connection. These totals never enter the
sampled Unix listener's counters. Four profiles therefore retain 400 raw Unix
samples and verify 480 sampled client lifecycles, with 1,966,080 observed bytes
per direction on sampled listeners; the 24 additional verification client
lifecycles and their 280,064 bytes per direction remain separately identified.

The sampled Unix socket is created only under the owned private fixture
directory. Both native and framework listeners use mode **0600**. Its socket
type, owner, device and inode are checked after bind and again immediately
before close; the path must be absent after close. Only boolean ownership and
retirement evidence and the configured mode enter reports. No path, device,
inode, payload or credential data is retained, and no custom unlink operation is
introduced. The parent removes its own temporary fixture directory after every
profile's processes have exited.

Two resource windows remain distinct. `resource` samples the server worker
during warmup and measured callbacks, including Tinybench import, and excludes
the earlier protocol verification and later completion/closure. Client process
startup, IPC and exit are part of callback elapsed time, but client CPU and RSS
are not part of this server-only process sample. `processTreeResource` covers the
entire supervised worker lifecycle, including server startup, all verification
and sampled client descendants, telemetry export and cleanup. The comparison
parent, its diagnostic collector, certificate creation and the Python observer
are excluded. The broader window cannot be interpreted as CPU spent only on
the 100 measured Unix echoes. Neither window measures filesystem/kernel buffer
memory or calibrates a production overhead budget.

## TLS 64-byte client lifecycle sampling

`--smoke-tls` selects the R6 TLS/TCP **64-byte** echo scope. It leaves `--verify`,
TCP `--smoke` and Unix `--smoke-unix` selections unchanged. Both direct native
`tls.createServer` and framework `createTlsServer` use a distinct sampled listener
with minimum TLS **1.3**. The five original untimed protocol scenarios retain
their TLS 1.2 minimum and their existing result fields. Their hostname control
must specifically fail with native `ERR_TLS_CERT_ALTNAME_INVALID`; the independent
child forwards only that allowlisted code and a fixed safe error, never native
certificate diagnostics.

The sampled listener accepts 120 independent clients per profile: 20 warmups and
100 raw Tinybench samples. Each fresh child trusts only the owned fixture
certificate, verifies its exact hostname, completes a nonresumed handshake and
checks every echoed byte. No TLS session, socket or client pool is shared across
callbacks. The listener independently requires 120 accepted connections and
**7,680 application bytes per direction**, then closes. Four profiles retain
400 raw samples, verify 480 authorized nonresumed handshakes and observe
**30,720 application bytes per direction** on sampled listeners. The original
24 verification client lifecycles and 280,064 bytes per direction are separately
reported; their deliberately rejected TLS hostname connections never enter the
sampled listener or its byte counters.

Every sampled client records actual native TLS protocol and cipher, peer
authorization and session-reuse status. The certificate public key is inspected
as EC `prime256v1`; its 256-bit size is identified from that P-256 named curve.
This certificate key is distinct from the ephemeral exchange key. When Node
exposes `getEphemeralKeyInfo()`, its actual type and available name/size fields are
recorded separately. Native hybrid groups may expose a group name without a
size; the size field remains absent in that case. If no metadata is exposed, the
field is `null`, without an invented value. Reports
contain no certificate, key, SAN, endpoint, marker or credential-file path.

The existing generic `firstByteMs` and `exchangeElapsedMs` observations remain
available. Only TLS sampling adds these monotonic event windows:

| Field                      | Observed interval                                                        |
| -------------------------- | ------------------------------------------------------------------------ |
| `tcpConnectElapsedMs`      | Immediately before native TLS client construction through TCP `connect`  |
| `handshakeElapsedMs`       | TCP `connect` through TLS `secureConnect`                                |
| `firstByteFromConnectMs`   | The same construction origin through the first incoming application byte |
| `exchangeFromConnectMs`    | The same construction origin through application stream end              |
| `payloadFirstByteMs`       | TLS `secureConnect` through the first incoming application byte          |
| `payloadExchangeElapsedMs` | TLS `secureConnect` through application stream end                       |

CA-file reading occurs before the TLS construction origin. Certificate metadata
inspection occurs after the application-end timestamp. Both remain inside the
outer Tinybench callback, which includes complete child startup, IPC, connection,
handshake, echo verification, resource retirement and physical process exit.
Client event-loop scheduling remains part of its observed intervals. No field
claims isolated cryptographic CPU time or a steady-connection payload benchmark.

The existing server-only and whole-process-tree resource windows retain their
different meanings. The broader supervised window includes the real independent
TLS clients and their metadata validation; the server-only window does not
include client CPU or RSS. All children must retire, resource observations must
remain accessible and SDK privacy/drop checks must pass. This bounded sample
does not establish TLS-engine handshake capacity, calibrated protocol-equivalent
framework overhead, production resource budgets, five paired repetitions,
one-hour soak or release acceptance.

## TCP 64 KiB client lifecycle sampling

`--smoke-tcp64k` adds the separate R6 TCP **64 KiB** echo scope:

```sh
ARKENIVA_SOCKET_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation socket --smoke-tcp64k /private/socket-tcp64k-smoke
```

The original TCP `--smoke` continues to use **64 bytes**. This explicit mode uses
one distinct sampled listener and 120 fresh independent client processes per
profile: 20 warmups and 100 retained Tinybench samples, at concurrency one. Each
client reassembles arbitrary stream chunks and verifies the complete 65,536-byte
echo. The listener independently requires 120 accepted connections and exactly
**7,864,320 application bytes in each direction**, then closes. The 100 measured
callbacks account for 6,553,600 bytes per direction; warmups account for 1,310,720.
These portions derive from checked callback counts and fixed payload size.

Four profiles therefore retain 400 raw latency samples and verify 480 sampled
client lifecycles with **31,457,280 observed bytes per direction**. The five
original verification scenarios, their 24 additional waited client processes and
280,064 bytes per direction remain separate from sampled counters. Neither
stream chunks nor calls to native `write` are treated as application frames.

The outer callback includes client startup, IPC, connect, complete echo and
physical client exit. Inner first-byte and exchange timings exclude startup and
IPC. Existing server-only and whole-process-tree resource windows remain
separate. Lifecycle throughput includes process creation and connection setup;
it does not establish sustained connection throughput, backpressure capacity,
calibrated framework overhead, five paired trials, one-hour soak or release
acceptance. The direct native baseline still omits framework admission, queue,
cancellation and lifecycle policy.

## UDP 256-byte client lifecycle sampling

`--smoke-udp` selects the R6 UDP **256-byte**, IPv4 loopback echo scope:

```sh
ARKENIVA_SOCKET_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation socket --smoke-udp /private/socket-udp-smoke
```

Each profile starts a distinct sampled UDP listener and 120 fresh independent
client processes at concurrency one: 20 warmups and 100 retained Tinybench
samples. A client accepts an echo only from the owned listener's actual address
and port, waits for its own native send callback and checks every echoed byte.
Foreign-source datagrams cannot satisfy the exchange. Missing or corrupt replies
fail the campaign; there is no retry or silent removal of failed observations.

The listener independently observes exactly **30,720 application bytes per
direction**, 120 admitted handler calls and 120 completed native reply callbacks.
It must close with no active handlers or socket or handler errors. The
framework's actual application-drop counter must remain zero; the direct native
baseline reports `observedApplicationDrops: null` with explicit
`not-applicable-no-application-drop-queue` provenance. A UDP listener accepts no stream connections. Four profiles
therefore retain 400 raw lifecycle samples, verify 480 client request/reply
exchanges and observe **122,880 bytes per direction**. The five original untimed
verification scenarios and their bytes remain separately reported.

Both the direct native echo path and framework benchmark handler record bounded
monotonic durations from handler entry through the reply callback. Twenty warmup
and 100 measured handler observations are retained separately. These server
handler intervals differ from the client's inner exchange and first-byte
intervals, and from the outer Tinybench callback including process startup, IPC
and physical client exit. Lifecycle operations per second do not establish
sustained datagram processing capacity. Resource windows retain the server-only
and whole-process-tree meanings described above.

The framework's application-drop counter observes its own bounded admission and
queue policy. The direct native baseline has no application drop queue. Neither
counter measures kernel, network or remote loss; `osNetworkLoss` remains `null`
and `deliveryGuaranteed` remains `false`. These bounded local observations do
not establish UDP reliability, many-sender capacity, calibrated overhead,
production budgets, five paired trials, one-hour soak or release acceptance.
