<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native socket interoperability verification

Build the workspace, make OpenSSL available and choose a fresh absolute external
report directory:

```sh
pnpm --filter @arkenivajs/benchmark-foundation socket --verify /private/socket-verification
ARKENIVA_SOCKET_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation socket --smoke /private/socket-smoke
ARKENIVA_SOCKET_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation socket --smoke-unix /private/socket-unix-smoke
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
remain unknown. TLS and UDP remain functional verification, and no handshake-rate
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
