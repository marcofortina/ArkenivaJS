<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native XLSX workbook interoperability comparison

Build the workspace and select a fresh absolute report directory outside it:

```sh
pnpm --filter @arkenivajs/benchmark-foundation xlsx --verify /private/xlsx-verification
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

Only `--verify` is supported, with no latency/resource samples and
`releaseGate: false`. Sampling requires complete native child CPU/RSS accounting,
first-row latency, peak-buffer and large-file heap measurements. Performance
budgets, five paired repetitions and a one-hour soak remain separate work.
