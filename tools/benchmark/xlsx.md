<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native XLSX workbook interoperability comparison

Build the workspace and select a fresh absolute report directory outside it:

```sh
pnpm --filter @arkenivajs/benchmark-foundation xlsx --verify /private/xlsx-verification
ARKENIVA_XLSX_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation xlsx --smoke /private/xlsx-smoke
```

Four isolated processes use native ExcelJS, the public workbook plugin, and
actual standard/detailed SDK profiles. In each, the selected adapter reads a
native workbook and the native adapter independently reads its output. Exact
sheet order, five rows across two sheets, leading-zero strings, Unicode,
booleans, interior nulls, Dates, number formats, bold text and font colors must
survive. A formula whose cached result deliberately differs from its calculated
value proves that formulas remain data. Formula-like text stays text.

Native input enters the selected adapter through one fresh single-pass source
with seven-byte compressed fragments. The target callback yields asynchronously;
successful write acknowledgement requires all callbacks to finish sequentially.
Receipts must match actual sheet/row and collected byte counts. Temporary input
staging is not enabled. Synthetic sheet names and cell contents must stay out of
reports and actual SDK exports.

The native baseline uses the ordinary bounded ExcelJS object model for this
small corpus. The framework uses bounded archive inspection, ordered worksheet
decoding and independently owned native children. This proves format
interoperability without claiming equivalent streaming cost, arbitrary workbook
fidelity or a complete hostile-input policy in the baseline.

`--verify` preserves this interoperability corpus without latency samples.
Unmarked `--smoke` rejects before worker or report creation. Explicit disposable
sampling first verifies interoperability, then reads one fixed 7,283-byte
compressed workbook: the same byte sequence and SHA-256 in every profile. Its
five rows across two worksheets were written by pinned ExcelJS 4.4.0; only ZIP
member timestamps were normalized using the standard ZIP library. Every member
body remains unchanged. The fixture is data, not a spreadsheet calculation engine.

The sole timed scenario performs exactly 20 warmup reads and 100 retained
Tinybench samples. Each callback creates one fresh single-pass source with
seven-byte compressed fragments, opens a reader, traverses both sheets in order,
validates every typed value and supported style, and awaits reader closure.
Formula caches remain deliberately uncalculated. Concurrent or excess callbacks
fail; up to 120 compact numeric results are retained within a ceiling of 128.
First-row latency starts before open and includes input/archive/metadata work.
Complete callback timing also includes validation and physical reader closure;
rows per second describes this small validated read, not bulk spreadsheet speed.
The input hash must remain unchanged after the whole corpus.

Linux supervision includes the profile worker and every native reader child,
startup, verification, warmup, sampling, export and cleanup. All owned children
must be waited, with no inaccessible or truncated observations. A trusted
90-second whole-profile controller budget allows the 120 fresh isolated reads;
the public 10-second per-operation policy, memory, concurrency, permissions and
isolation stay unchanged. Aggregate CPU and sampled summed RSS describe that
lifecycle. Shared pages may be counted repeatedly and brief peaks may be missed;
RSS is neither exact peak memory nor PSS. Opaque internal buffer sizes remain
unknown, and the independent native object model has different isolation costs.

Reports retain `releaseGate: false`. Write timing, large-file heap/peak-buffer and
backpressure acceptance, calibrated policy-equivalent budgets, five paired
repetitions and a one-hour soak remain separate work.
