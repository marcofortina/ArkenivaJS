<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native barcode comparison and bounded smoke

Build the workspace and select a fresh absolute output directory outside Git:

```sh
pnpm --filter @arkenivajs/benchmark-foundation codes --verify /private/codes-verification
```

Four sequential isolated Node profiles exercise bare qrcode/bwip/Sharp/ZXing,
the public barcode plugin and the actual standard/detailed diagnostic SDK modes.
Each roundtrips real PNG images for QR, CODE128 and EAN13 and generates QR SVG.
The tests additionally decode each encoder's images with the other service and
check that image input bytes remain unchanged. Verification retains its original
direct fork, `measured:false`, null resources and no timing samples.

Use an owned disposable VM for real measurements:

```sh
ARKENIVA_CODES_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation codes --smoke /private/codes-smoke
```

Smoke opts all four profiles into the same Linux process-tree supervisor. Each
profile performs four sequential scenarios: QR PNG generation at width 256 and
correction M; CODE128 and EAN13 PNG generation at maximum width 512; and decoding
the identical fixed 256×256 QR PNG. Each scenario has 20 excluded warmup callbacks
and 100 retained actual Tinybench latency samples in milliseconds: 1,600 measured
samples and 320 warmup callbacks across four profiles. `--full` remains unsupported.
The native encoder uses the same explicit upstream SVG-to-Sharp pipeline, QR
margin/correction and barcode scale selection as the public fixed-corpus operation.
Bare upstream does not claim equivalent adversarial image policies or process isolation.

`codes-fixture.mjs` contains a fixed 1,829-byte PNG from pinned qrcode 1.5.4,
width 256, margin 4, correction M. Its SHA-256 is
`c6f176aa9d93d8abe28fed803dd7a85abcb9f97e51480119923ae56806a60af2`.
Decode input is independent of the encoder being timed, has the same hash in every
profile, and must remain unchanged. The synthetic URL is a data carrier and is
never followed or interpreted as authentication.

Encoding callbacks retain at most 120 private outputs per scenario, at most 64 KiB
per image and 8 MiB in total. Completion uses independent direct Sharp metadata
inspection and ZXing decoding for every rendered image, checking exact contents,
symbology and consistent dimensions. It releases the private corpus and reports only
counts, total encoded bytes, pixels, dimensions and digests. Every decode callback
checks the expected text/symbology. No PNG payload or symbol contents enter reports
or telemetry. Per-operation latency includes actual codec work and bounded capture
or assertion cost; independent completion checks are outside those latency samples.

The framework keeps a one-process codec pool, 5-second operation deadlines,
262,144-pixel cap and 64-KiB input/output limits. The supervisor keeps its existing
30-second per-profile deadline and 1-MiB result limit. A profile fails on missing
resource access/discovery or incomplete physical cleanup; limits are not increased
to force a successful measurement. Every owned codec process must exit.

Reports preserve original measured-window worker CPU, heap, GC and event-loop fields.
Separate `processTreeResource` reports whole-lifecycle Node bridge/worker/codec CPU
and RSS, including startup, verification, warmup, measured work, independent completion
checks, export and cleanup. Python observer and parent/collector CPU are excluded.
Sampled RSS sums can repeat shared pages and miss brief peaks; maximum single-process
RSS remains a separate value. These are aggregate observations, not per-operation
native allocation costs. Retention/copy and independent checker costs are included
in the corresponding whole-lifecycle resources. See [resource scope](supervised-resources.md).

Actual standard/detailed metrics reach the owned collector; privacy and SDK
drop/export checks remain active. Both modes force diagnostic samplingRatio=1,
which establishes no normal production sampling budget. Generation and detection
use pinned qrcode 1.5.4, bwip-js 4.11.4, Sharp 0.35.5 and ZXing 0.21.3; no decoder
algorithm is implemented by this tool. Smoke is a short closed-loop measurement,
with `measured:true` and `releaseGate:false`. It proves no calibrated observer/IPC
overhead, open-loop load equivalence, confidence intervals, performance budget,
five-run campaign, one-hour soak, release readiness or production policy equivalence.

The explicit integration test runs only with the same disposable opt-in:

```sh
ARKENIVA_CODES_BENCHMARK_DISPOSABLE=1 node --test tools/benchmark/test/codes-smoke.integration.test.mjs
```
