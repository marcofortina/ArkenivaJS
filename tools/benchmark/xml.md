<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native ordered XML interoperability verification

Build the workspace and choose a fresh absolute external report directory:

```sh
pnpm --filter @arkenivajs/benchmark-foundation xml --verify /private/xml-verification
```

Four isolated profiles compare native `fast-xml-parser`/`saxes` with the actual
XML service and standard/detailed SDK instrumentation. Three self-contained
documents exercise ordered mixed content, Unicode/entities, string attributes
with leading zeros, namespace prefixes, CDATA and comments. Expected trees are
checked explicitly; native and public writers are independently parsed on both
paths. Object prototypes are normalized only for semantic tree comparison.

The native baseline uses native SAX syntax/namespace validation, explicit DTD
rejection and ordered native parsing/writing. It omits framework hostile-object
capture, complete security limits, finite worker isolation, deadlines, cancellation,
expanded-name policy and lifecycle checks. Negative tests reject malformed syntax,
invalid UTF8 and DTDs on both paths. Actual SDK exports and structured reports must
exclude document content and namespaces. Application shutdown awaits its workers.

Only `--verify` is supported. Sampling is rejected before workload allocation
until complete worker CPU/heap accounting is available. Reports retain
`releaseGate: false`. This corpus makes no XSD validation claim: well-formedness
does not establish schema acceptance, and the separately vetted external XSD
engine remains an independent workload. Dedicated-runner budgets, five paired
repetitions and one-hour soak acceptance are not established here.
