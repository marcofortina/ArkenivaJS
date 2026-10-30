<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native XML interoperability and bounded XSD smoke

Build the workspace and choose a fresh absolute external report directory:

```sh
pnpm --filter @arkenivajs/benchmark-foundation xml --verify /private/xml-verification
```

Four isolated profiles compare native fast-xml-parser 5.11.2 and saxes 6.0.0 with
actual public XML and standard/detailed SDK instrumentation. Three self-contained
documents exercise mixed-content order, Unicode/entities, leading-zero string
attributes, namespaces, CDATA and comments. Expected trees are checked explicitly;
native and public writers are independently parsed on both paths. Verification
keeps its original direct fork, `measured:false`, null resources and no timing
samples. It requires no native XSD installation and makes no XSD validity claim.

Real smoke requires the existing owned disposable XML fixture, reviewed libxml2
and libxml2-utils version `2.9.14+dfsg-1.3ubuntu3.10`, and the unchanged network
namespace launcher. Installations belong only in the previously approved disposable
VM/CI setup. The benchmark installs nothing and has no parser-only XSD fallback:

```sh
ARKENIVA_XML_DISPOSABLE=1 python3 examples/xml/test/fixtures/run.py -- node tools/benchmark/xml.mjs --smoke /private/xml-smoke
```

The launcher establishes a separate network namespace containing only loopback,
then drops root groups and privileges. The coordinator requires its existing
explicit disposable/namespace markers and verifies actual non-root loopback-only
membership. Safe-env workers inherit the OS namespace and check its captured inode
and actual interfaces; no marker or unrelated environment is forwarded through the
supervisor. Public XSD engine identity, reviewed versions, offline-import graph and
private snapshot gates remain active. `--full` remains unsupported.

Smoke measures only **XSD validation** of the same small fixed UTF-8 invoice in
every profile. It performs 20 excluded warmup callbacks and 100 retained Tinybench
latency samples per profile: 400 measured samples and 80 warmup validations across
four profiles. Every callback awaits real schema validation and checks the exact
validity report, with bounded capture/assertion overhead. Input bytes must remain
unchanged after every callback. Parser/writer behavior remains verified before
timing, including the fixed invoice, but this smoke makes no parser/writer timing
claim. Startup distinguishes an actually valid decimal from a well-formed but
schema-invalid decimal and rejects an unregistered schema ID. XML well-formedness
alone never establishes XSD acceptance.

Both paths use the existing product assets
`examples/xml/test/fixtures/invoice.xsd` and `types.xsd`, with recorded SHA-256 values
from `xml-xsd.mjs`. They are copied only to a private operational directory outside
Git (0700 directory, 0600 files) and removed on success or failure. Their fixed schema
IDs and relative offline include are preserved. No application request chooses
schema paths. Native validation uses the
same reviewed xmllint backend, `--nonet`, `--nocatalogs`, fixed stdin, and finite
prlimit CPU/address-space/data/file/descriptor bounds without a shell. Native
stdout/stderr are drained under a 64-KiB ceiling and never exposed as XML diagnostics.
Its 2-second command deadline awaits actual process close, including on failure.

At most 120 private validation reports, each at most 512 bytes and at most 64 KiB
in total, are retained. Completion independently parses the fixed input with native
SAX/ordered parsing, checks its exact expected semantics, and verifies its validity
again with real native XSD. Every retained validity report must match that independent
known outcome. Reports expose exact callback/validation/check counts, consumed input
bytes, retained report bytes and SHA-256 digests; retained report data is released.
Documents and namespaces never enter SDK payloads or reports. Independent completion
checks remain outside measured latency and inside whole-lifecycle resource accounting.

All four measured profiles use the same process-tree supervisor. Original
measured-window worker CPU/heap/GC/event-loop fields remain intact. Separate
`processTreeResource` includes whole-lifecycle Node bridge/worker CPU, Worker-thread
CPU within its process, and actual waited dpkg/xmllint child CPU. It includes startup,
verification, warmup, measured work, independent fixed-document/report checks, export and physical
cleanup. Python observer and parent/collector resources are excluded. Sampled RSS
sums are non-atomic, may repeat shared pages and miss short-lived peaks; maximum
single-process RSS remains separate. Worker-thread heap allocation is not presented
as an exact per-operation/native-process heap total. Inaccessible/truncated resource
observations or unfinished descendants fail the comparison. Existing 30-second
per-profile and 1-MiB worker-result limits remain unchanged.

The public parser retains its full hostile-object, resource, DTD/XXE, namespace,
Worker-thread isolation, timeout, cancellation and lifecycle policies. The fixed
native baseline does not claim equivalent adversarial-input policy. Actual SDK
exports preserve privacy and zero-drop/export-error checks. Standard/detailed force
diagnostic samplingRatio=1, which establishes no normal production budget. Smoke
uses `measured:true` and `releaseGate:false`; it establishes no calibrated observer
cost, matched open-loop load, confidence intervals, release budget, five repetitions,
one-hour soak, production readiness or complete XML/XSD performance acceptance.

The dedicated integration must use the same isolated fixture:

```sh
ARKENIVA_XML_DISPOSABLE=1 python3 examples/xml/test/fixtures/run.py -- node --test tools/benchmark/test/xml-smoke.integration.test.mjs
```
