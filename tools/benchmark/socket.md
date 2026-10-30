<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native socket interoperability verification

Build the workspace, make OpenSSL available and choose a fresh absolute external
report directory:

```sh
pnpm --filter @arkenivajs/benchmark-foundation socket --verify /private/socket-verification
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
cancellation and lifecycle policy. `--smoke` is rejected before fixture allocation:
first-byte/backpressure measurements, handshake rates and complete independent
client/server CPU accounting remain separate work. Dedicated-runner budgets, five
paired repetitions and one-hour soak acceptance are not established here.
