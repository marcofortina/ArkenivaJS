<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native PDF interoperability and bounded inspection smoke

Build the workspace and select a fresh absolute directory outside it:

```sh
pnpm --filter @arkenivajs/benchmark-foundation pdf --verify /private/pdf-verification
```

Four isolated comparison processes use pinned pdf-lib 1.17.1/PDF.js 6.4.299,
the public document plugin and actual standard/detailed SDK profiles. Each verifies
all five public operations against small synthetic searchable PDFs. Native engines
read public created/modified output, and the public service reads independently
created native input. Checks include private metadata, text geometry, rotated text
and exact three-page merge order. Helvetica and explicit coordinates avoid host font
discovery. Verification retains its original direct fork, `measured:false`, null
resource fields and no timing samples.

Real measurements require an explicitly owned disposable VM:

```sh
ARKENIVA_PDF_BENCHMARK_DISPOSABLE=1 pnpm --filter @arkenivajs/benchmark-foundation pdf --smoke /private/pdf-smoke
```

Smoke times only **inspection** of the identical fixed 1,301-byte unsigned inactive
one-page PDF. It uses all four supervised profiles, 20 excluded warmup callbacks and
100 actual retained Tinybench latency samples per profile: 400 measured samples and
80 warmup inspections. `--full` remains unsupported. The native baseline uses both
pdf-lib and PDF.js, comparing page count and metadata before returning its report.
Each public call retains its actual bounded owned codec process, isolation and
lifecycle; no process pool is introduced or reused to reduce measured overhead.
Other PDF operations remain functional checks and have no timing claim in this smoke.

`pdf-fixture.mjs` contains a PDF created once using pinned pdf-lib 1.17.1, one A4
page, Helvetica size 12, fixed synthetic metadata/text and fixed UTC dates of
2026-01-01. Object streams are disabled. The exact input SHA-256 is
`96a406656f863df530d5aa264f06ed5b365addbb7cdec5808173ceeced1e5799`.
The document is independent of the service under measurement and never written to
disk. Every inspection checks exact page/encryption/signature flags and metadata;
its source bytes must remain unchanged. The synthetic unsigned input does not test
signature authenticity or prove signature-policy equivalence.

At most 120 private metadata reports, each at most 2 KiB and at most 256 KiB in total,
are retained. Completion independently loads the input with pdf-lib and extracts
its searchable text with PDF.js, checking page counts, title/author and exact text.
All retained inspection reports must agree with that document. Reports export only
exact operation/report/page counts, consumed input bytes, report bytes and SHA-256
digests, then release retained values. Document bytes, title, author and text never
enter telemetry or reports. Measured latency includes actual inspection plus bounded
capture/assertion costs; independent completion checks are outside those samples.

All profiles use the same process-tree supervisor and preserve original worker
measured-window CPU/heap/GC/event-loop fields. Separate `processTreeResource` covers
whole-lifecycle Node bridge/worker/native-child CPU and RSS: startup, five-operation
verification, warmup, inspection, independent completion checks, export and physical
cleanup. Python observer and parent/collector resources are excluded. RSS sums are
sampled and non-atomic, can repeat shared pages and miss brief peaks; maximum
single-process RSS remains separate. Heap fields do not claim exact child allocation
costs. Inaccessible/truncated observations or unfinished descendants fail comparison.
The trusted controller explicitly selects a 90-second whole-profile deadline for
this cold-process inspection smoke. It covers startup, verification, 20 warmups,
100 measured inspections and cleanup, within the supervisor's existing 120-second
ceiling. Each public PDF operation retains its existing 10-second decode/operation
limit, memory bounds, permissions and isolation. The 1-MiB worker-result limit is
unchanged. This controller setting does not alter verification or other adapters.
The dedicated integration has a bounded 420-second outer timeout for four profiles
and cleanup; it does not replace any per-operation deadline.

Actual SDK privacy/drop/export checks remain active. Standard/detailed force
diagnostic samplingRatio=1, which establishes no normal production sampling budget.
The native corpus baseline does not duplicate the complete framework signature,
active-content, resource, permission, cancellation or lifecycle policies. This is
not a hostile-PDF, Unicode embedding, signature-preservation, OCR, rendering or font
fidelity test. It uses `measured:true` and `releaseGate:false`, establishing no
calibrated observer cost, matched open-loop load, confidence intervals, performance
budget, five repetitions, one-hour soak or complete PDF performance acceptance.
No PDF, font or cryptographic parser is implemented by the tool.

The dedicated integration runs only with the same disposable opt-in:

```sh
ARKENIVA_PDF_BENCHMARK_DISPOSABLE=1 node --test tools/benchmark/test/pdf-smoke.integration.test.mjs
```
