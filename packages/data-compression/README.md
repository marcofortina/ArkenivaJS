<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Bounded compression and archives

Register `dataCompressionPlugin({ defaults: {}, policy: { maxConcurrent: 1, timeoutMs: 5000 } })`,
start the application and resolve `COMPRESSION_CAPABILITY` as `CompressionService`.
The [executable example](../../examples/compression/README.md) uses public types only.
Importing this package creates no connections, files, worker threads or timers.

`gzip` and `gunzip` accept bytes or a single-pass `AsyncIterable<Uint8Array>` and
return native Node GZIP streams. `createZip` accepts synchronous/asynchronous entries
with explicit relative names and byte sources, and returns an fflate 0.8.3 ZIP stream.
The framework implements no compression algorithm or ZIP parser. The explicit yauzl
3.4.0 reading adapter supplies central/local headers, entry attributes, names and
bounded native inflation; Node's `crc32` verifies entry contents. Both dependencies
are MIT licensed and retain their own upstream notices. fflate remains the ZIP writer.

`iterateZip` buffers only the bounded compressed archive, preflights its entire
catalog, then reads and verifies one bounded entry before yielding it. Each entry's
`data` is a single-pass stream over verified owned bytes, with no native handle;
it can be consumed independently after the outer iterator advances. Entry contents
are not accumulated by the service across yielded entries. This is bounded archive
iteration, not a constant-memory remote ZIP decoder. No URL is downloaded and no
filesystem extraction, temporary file, symlink or directory is created.

Catalog checks reject traversal, absolute/drive paths, backslashes, empty/dot path
segments, control bytes, Windows reserved names, trailing dots/spaces and unsupported
Unix entry types including symlinks. Names are NFC-normalized; NFKC uppercase collision
keys also reject duplicate/case/normalization collisions and file/directory ancestor
conflicts. Native local and central filenames, flags and compression methods must
agree. Encrypted/unsupported entries reject. A trailing slash denotes an empty
directory. CRC and actual expanded-size mismatches reject before yielding that entry.
Errors in a later entry still fail the outer iterator; consumers must exhaust every
operation to establish successful completion. Streamed GZIP/ZIP prefixes are not
complete verified archives until their iterator finishes successfully.

Deployment defaults: 16 MiB compressed, 64 MiB expanded, ratio 100, 1000 entries,
depth 16, 8 MiB per entry and 5000 ms CPU budget. Fixed ceilings are 64 MiB compressed,
expanded and per-entry, ratio 10000, 4096 entries, depth 64 and 120000 ms CPU.
Ratio is a positive finite number; other numeric limits are positive safe integers.
Runtime concurrency is required (1–16), with a required positive timeout up to 120000 ms.
Runtime input/output byte defaults are 16/64 MiB and cannot exceed 64 MiB each.
The effective byte ceilings are the smaller of the operation's directional limit
and deployment input/output limits. Per-call limits and deadlines can only tighten
deployment settings. Nothing is silently truncated.

Native streams and source read-ahead are bounded; fflate receives chunks of at most
16 KiB and emits under the total compressed-output cap. Both encoding and decoding
check expansion ratios. ZIP metadata allows rejecting declared bombs before inflation;
actual bytes and CRC are still checked. Input byte arrays are snapshotted without
calling caller-owned iterators/accessors; shared-memory views are rejected. Archive
buffers and one verified entry require bounded copies, not an OS RSS guarantee.

There is no admission queue or implicit retry. Abort/deadline/iterator return destroys
owned native streams; paused consumers also expire. Native and user tasks are observed
from birth and retain physical admission until they settle. A producer ignoring abort
cannot be forcibly preempted by JavaScript; it retains its permit and application
shutdown remains bounded by the core's shared shutdown deadline. Closed services
reject new work. Returned verified entry bytes are ordinary owned output data.

The CPU ceiling conservatively charges the process CPU delta during the operation,
including other concurrent work; it is not isolated per-operation or tenant CPU
accounting. Checks run between bounded chunks and on a timer, before acknowledging
output. The monotonic wall deadline independently bounds waits. No claim of an OS
CPU/memory quota or interruption in the middle of a native chunk is made.

Invalid configuration uses `EK_CONFIG_INVALID`; unsafe names/types use
`EK_ARCHIVE_PATH`, corrupt/unsupported/encrypted archives use `EK_ARCHIVE_CORRUPT`,
and finite resource bounds use `EK_ARCHIVE_LIMIT`. Common cancellation/deadline/closed
errors are `EK_ABORTED`, `EK_TIMEOUT`, `EK_RESOURCE_CLOSED`. Native errors, source
exceptions, abort reasons, paths and payloads never appear in logs or telemetry.

Optional existing logger/telemetry plugins receive fixed `compression.operation` and
`compression.outcome` labels, byte counts, ratio, duration and observed throughput.
`compression.process.cpu.ms` and `compression.process.rss.peak.bytes` are actual
process-wide window samples; they are not codec allocation or tenant usage claims.
Other instruments are `compression.duration.ms`, `compression.compressed.bytes`,
`compression.expanded.bytes`, `compression.ratio`, `compression.expanded.bytes_per_second`.
Observer errors cannot replace results, reread a producer or retry an operation.

Native interoperability, adversarial paths/CRC/bombs, backpressure, cancellation,
lifecycle and strict contract fixtures accompany the package. Performance campaigns
and remote architecture acceptance remain separate release gates.
