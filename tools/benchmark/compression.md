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

Only `--verify` is accepted. Reports use `measured: false`, null resource results,
no timing samples and `releaseGate: false`. `--smoke` fails before workers or
output directories start. Streaming measurement requires time-to-first-byte,
backpressure and observed buffer evidence; completed operation counts alone
cannot establish the required throughput or memory acceptance.

The bare baseline uses native streaming zlib and a buffered fflate ZIP operation
on a fixed small trusted corpus. It is not a safe remote-archive endpoint and
makes no equivalent CRC, traversal, symlink, ratio, cancellation or deployment
policy guarantee. The framework retains all its existing safety checks. ZIP
metadata and compressed byte encodings need not be identical; verified contents
and complete stream consumption are the functional comparison.

Actual standard/detailed operation metrics reach the owned collector. Contents
and entry names must not appear in telemetry or reports; SDK drop/export checks
remain active. No first-byte, backpressure, peak-buffer, throughput, repeated
campaign, one-hour soak or release performance budget is claimed.
