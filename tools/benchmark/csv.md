<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native CSV and TSV functional comparison

Build the workspace and select a fresh absolute directory outside Git:

```sh
pnpm --filter @arkenivajs/benchmark-foundation csv --verify /private/csv-verification
```

Four isolated Node profiles use csv-parse 7.0.3 and csv-stringify 6.9.0,
the public CSV plugin and the actual standard/detailed telemetry modes.
Every input and output stream is exhausted. The fixed corpus checks comma,
tab and semicolon delimiters, BOM, one-byte UTF-8 fragments, embedded newlines,
quotes, empty cells, Unicode, leading zeros and empty streams. Tests also
exchange native/public encoded rows in both directions, preserve input bytes
and prove that one-shot sources are consumed once.

`--verify` retains `measured: false`, null resources, no timing samples and
`releaseGate: false`; it runs no large pressure probe.

## Short measured stream comparison

Run measurements and large pressure probes only in the owned disposable QEMU
runner, requiring an explicit marker before worker or evidence creation:

```sh
ARKENIVA_CSV_BENCHMARK_DISPOSABLE=1 \
  pnpm --filter @arkenivajs/benchmark-foundation csv --smoke /private/csv-smoke
```

Two sequential scenarios parse and stringify 256 fixed valid text rows. Separate
scenarios preserve the existing `maxConcurrent: 1` policy; no simultaneous
same-service roundtrip is introduced. Each scenario/profile runs 20 warmup
callbacks then 100 actual retained Tinybench samples, using the existing pinned
native parser/writer. The parser receives 1024-byte fragments, including UTF-8
boundaries. The writer consumes fresh one-shot rows and emits a single BOM.
Each callback verifies exact row order/text, actual bytes and a SHA256 integrity
proof against independently prepared native fixture bytes. Only the small
bounded fixture is materialized; large probe files are never collected.

Per-callback observations retain first actual input time, first encoded output
byte/data byte for stringify or first emitted row for parse, elapsed stream
time, actual source/consumer pulls, rows, encoded byte counters, logical field
UTF-8 byte count and largest observed boundary chunks. The writer's first byte
may be only a BOM; first data byte is reported separately. No time for an
unobservable completed writer row is invented. Rows/sec and encoded bytes/sec
use actual counters and stream elapsed time, not completed-stream counts alone.
Decoded field UTF-8 bytes are logical text volume, not object allocation size or
wire bytes. Digest/assertion/timestamp collection overhead is included in this
diagnostic workload, equally in all profiles.

The pinned Tinybench implementation executes warmup before measured callbacks;
completion checks exact actual callback count against retained sample count plus
warmup count before marking the chronological stream observations by phase.
Raw Tinybench latency values remain actual samples; no equality or one-to-one
ordering between their result array and inner stream timestamps is assumed.
Only counts, durations and integrity hashes enter reports, never record content.

## Separate actual backpressure probes

After the samples, an untimed 8192-row/8 MiB lazy corpus probes each direction in
every profile. One preencoded 1024-byte record is reused; the source is ungated
and creates no full-file buffer. After consuming the first output/row, the
harness stops pulling output, allows actual pipelines to reach a stable producer
plateau, then observes a 50 ms consumer hold. Success requires unchanged producer
pull counts while held, strictly before source EOF, and a producer that is still
owned rather than already finished. The hold is a test observation, not a new
production deadline or latency budget. After resumption, all 8192 rows and exact
8 MiB encoded bytes must match their independent digest, sources must enter
`finally`, and both owned streams must physically close. A fresh tiny roundtrip
then proves the single-operation admission lane was released.

Common harness-owned Node Readable wrappers expose observed queue peaks in
explicit units: byte queues and object/row queues stay separate. Input/output
chunk maxima are observed boundary sizes. These are only the queues owned by the
harness; they do not measure opaque csv-parse/stringify or framework internal
buffers. `opaqueInternalBufferBytes` remains explicitly `null`/unknown, never a
fabricated zero. Queue sampling may miss transient peaks and is not an exact
process-RAM measurement. The corpus remains below existing 64 MiB/100000-row/1 MiB
record limits; no public runtime ceiling is raised or bypassed.

Measured-window `resource` describes the small sampled streams. Because pressure
probes run in completion, all profiles separately opt into
`superviseProcessTree:true` for whole-lifecycle CPU/RSS, including fixture setup,
verification, warmup, samples, probes, export and cleanup. Lifecycle values must
not be presented as measured-window CPU/request cost. Summed RSS observations
are sampled/non-atomic, can miss brief peaks and count shared pages per process;
they are neither PSS nor unique physical RAM. Parent collector/Python observer
resources are excluded. All owned processes must be waited and retired, with
accessible untruncated discovery/RSS observations. STANDARD and DETAILED both use
the shared helper's diagnostic sampling ratio 1, so STANDARD does not represent
normal production sampling. Probe fixture/digest preparation is outside probe
stream elapsed time but inside lifecycle resource observations.

This is a bounded component comparison and separate pressure observation, not a
stable throughput, exact peak-RAM or calibrated release-budget claim. Normative
long warmup/steady trials, five paired repetitions and one-hour soak remain
separate and deferred. Ordinary CPU/unit checks use only tiny bounded functional
streams and make no performance or pressure measurement.

The bare SDK baseline handles a fixed valid corpus. It does not reproduce
framework schema validation, finite resource admission, fatal UTF-8 handling,
spreadsheet formula policy or cancellation guarantees. These remain covered
by the runtime package tests. No full-file buffering occurs inside the native
adapter; the test verifier collects only the small fixed fixture for assertions.
Record contents must remain absent from telemetry and reports. No repeated
campaign, one-hour soak or release acceptance is claimed.
