<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native socket interoperability verification

Build the workspace, make OpenSSL available and choose a fresh absolute external
report directory:

```sh
pnpm --filter @arkenivajs/benchmark-foundation socket --verify /private/socket-verification
ARKENIVA_SOCKET_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation socket --smoke /private/socket-smoke
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
remain unknown. This is local TCP only: TLS, UDP and Unix transport remain
functional verification, and no handshake-rate or backpressure campaign is
claimed. Dedicated-runner budgets, calibrated policy-equivalent overhead, five
paired repetitions and one-hour soak acceptance remain separate work.
