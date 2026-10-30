<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native compression functional comparison

Build the workspace and select a fresh absolute output directory outside Git:

```sh
pnpm --filter @arkenivajs/benchmark-foundation compression --verify /private/compression-verification
```

Four sequential isolated Node profiles consume actual GZIP and ZIP work through
Node zlib, fflate 0.8.3 and yauzl 3.4.0, the public compression plugin and the
actual standard/detailed SDK modes. Every output stream and archive entry is
exhausted. Preflight checks native/public GZIP compatibility, zero-length input,
ZIP creation, entry names and exact binary contents. Tests additionally exchange
ZIP archives between both services, consume one-pass fragmented sources and
check that input archive bytes remain unchanged. No archive is written to disk.

`--verify` remains nonmeasured, with null resource results, no timing samples
and `releaseGate: false`; it runs no large pressure probe.

## Short GZIP/GUNZIP component comparison

Run measured and large probe work only inside the owned disposable QEMU runner:

```sh
ARKENIVA_COMPRESSION_BENCHMARK_DISPOSABLE=1 \
  pnpm --filter @arkenivajs/benchmark-foundation compression --smoke /private/compression-smoke
```

The explicit marker is required before workers or evidence creation. Two async
scenarios use the existing finite payload: GZIP followed by a bounded independent
native decode check, and GUNZIP of independently prepared native GZIP bytes.
Fixture encoding/digests are prepared before the samples, and each scenario
executes 20 warmup callbacks followed by 100 actual retained Tinybench latency
samples in all four profiles. The original ZIP entry/CRC/cross-library
verification remains unchanged and outside sampling. ZIP timing is explicitly
unsupported, rather than implied by a general measured report.

Every callback records actual first input/output byte, complete stream duration,
compressed and uncompressed byte counts, actual ratio, source/consumer pulls,
maximum observed boundary chunks, digest and producer retirement. Stream bytes/s
uses observed bytes and elapsed time, not completed-operation counts. GZIP first
output can be only a format header, not compressed payload completion. The
bounded independent decode/CRC/content check runs after the inner GZIP stream
duration; raw Tinybench latency and measured-window CPU include that validation
cost, which is disclosed rather than called pure codec cost. GUNZIP consumes
and validates its complete native stream and exact output digest. No compressed
byte representation is promoted to a public deterministic-encoding guarantee.

The pinned Tinybench order runs warmup before measurement. Actual call counts
must equal retained sample count plus warmup before chronological inner stream
observations are marked by phase; no raw latency-array ordering is assumed.
Private bytes and archive entry names stay out of SDK exports and reports.
Integrity digests are private benchmark evidence, not telemetry labels.

## Separate lazy pressure probes

Each profile then runs an untimed 8 MiB probe for GZIP and GUNZIP. A deterministic
64 KiB binary block is built from standard SHA256 fixture-counter outputs and
repeated lazily in 4096-byte pieces; its size exceeds zlib's 32 KiB history, yielding
a deliberately low-compressibility fixture rather than a ratio bomb. This is
synthetic reproducible data, not a cryptographic entropy or key-generation
algorithm. Actual ratios are observed and must remain within the existing
maxRatio 100, maxCompressedBytes 16 MiB, maxUncompressedBytes 64 MiB and existing CPU
limits. No limit is increased or bypassed and no full 8 MiB file is collected.

After the first output, the consumer stops pulling while ungated producers and
real native queues settle. Native zlib jobs can still complete asynchronously,
so stable producer observations precede a 50 ms hold; any observed progress resets
settling. Success requires an actual unchanged pull count strictly before EOF
and an owned unfinished producer during the final hold, not a producer that
already completed. The interval is a diagnostic observation, not a production
latency target. On resumption, all bytes, source `finally`, known stream closure
and full native semantic integrity must pass, followed by a tiny healthy
roundtrip proving the single-operation lane was released.

For GZIP, a native validation decoder consumes the encoded output after the
consumer hold and checks the complete 8 MiB plaintext digest without full-file
buffering. For GUNZIP, a native upstream GZIP fixture generates encoded input
lazily, also without full buffering or overlapping two public compression calls.
Both auxiliary codecs remain owned and retired. Probe elapsed/lifecycle CPU
explicitly includes fixture/validation work; probe values cannot be called pure
standalone GZIP or GUNZIP cost. First source-production time and first actual API
input time are distinct, since the GUNZIP fixture encoder runs upstream.

Observed harness-owned Readable byte-queue peaks and boundary chunk maxima stay
separate from opaque codec/framework internal buffers, which remain
`null`/unknown. Queue observations can miss transient peaks and are not exact
RAM measurements. Small `resource` observations cover warmup/samples only;
all profiles separately opt into `superviseProcessTree:true` so lifecycle CPU/RSS
also covers probes, export and cleanup. Node zlib/libuv worker-thread CPU/RAM is
included in its owning process. Python observer and parent collector resources
are excluded. All processes must be waited/retired, discovery/RSS reads accessible
and untruncated. RSS sums are sampled/non-atomic, may repeat shared pages and
miss brief peaks; they are not PSS or unique physical RAM. STANDARD and DETAILED
both use the shared helper's diagnostic sampling ratio 1, so STANDARD here does
not represent normal production sampling.

These are bounded component observations, not calibrated throughput/memory
budgets, exact peak-RAM or complete archive-policy equivalence. Normative long
warmup/steady trials, five paired repetitions and one-hour soak remain separate
and deferred. Ordinary unit checks use only the tiny functional corpus; the
explicitly marked integration case alone enables measured and large probe work.

The bare baseline uses native streaming zlib and a buffered fflate ZIP operation
on a fixed small trusted corpus. It is not a safe remote-archive endpoint and
makes no equivalent CRC, traversal, symlink, ratio, cancellation or deployment
policy guarantee. The framework retains all its existing safety checks. ZIP
metadata and compressed byte encodings need not be identical; verified contents
and complete stream consumption are the functional comparison.

Actual standard/detailed operation metrics reach the owned collector. Contents
and entry names must not appear in telemetry or reports; SDK drop/export checks
remain active. ZIP streaming/first-byte/backpressure timing, repeated campaigns, one-hour
soak and release performance budgets remain open; GZIP/GUNZIP smoke observations
are limited to the scope above.
