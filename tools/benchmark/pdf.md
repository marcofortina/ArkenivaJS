<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native PDF document interoperability comparison

Build the workspace and select a fresh absolute directory outside it:

```sh
pnpm --filter @arkenivajs/benchmark-foundation pdf --verify /private/pdf-verification
```

Four isolated comparison processes use direct pdf-lib/PDF.js, the public document
plugin and actual standard/detailed SDK profiles. Each exercises all five public
operations against small synthetic searchable PDFs. The native engines read the
adapter's created and modified output; the adapter reads independently created
native input, including a private title. Tests check text geometry, retained
rotated text and the exact three-page merge order. The standard Helvetica font
and explicit coordinates keep the corpus independent of host font discovery.

Actual SDK exports and reports exclude document text and title. Source/target
bytes remain bounded memory values; the tool writes no document to disk. Native
SDK primitives and parsing remain confined to the owned comparison processes.
No PDF, font, rendering, bidi or cryptographic parser is implemented by the tool.

The native baseline performs basic native signature-field/permission inspection
on this unsigned inactive corpus. It does not duplicate the framework's complete
signature/active-content policy, process isolation, resource bounds or lifecycle.
This is not a hostile-PDF, Unicode embedding, signature-preservation, OCR or
rendering acceptance test.

Only `--verify` is supported, with no latency/resource samples and
`releaseGate: false`. Parent-only CPU/RSS would omit the framework's owned native
children, so sampling is rejected until complete process accounting is available.
Pages/sec, memory peaks, dedicated-runner budgets, five repeated trials and a
one-hour soak remain separate work.
