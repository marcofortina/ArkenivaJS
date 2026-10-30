<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native verified-HTTPS SOAP interoperability

Build the complete workspace, including compiled SOAP conformance fixtures, make
OpenSSL available and choose a fresh absolute external report directory:

```sh
pnpm --filter @arkenivajs/benchmark-foundation soap --verify /private/soap-verification
```

Four isolated profiles compare pinned node-soap/Axios with the public SOAP
service and actual standard/detailed SDK instrumentation. The tool reuses the
independently authored compiled conformance WSDL. An actual native SOAP server
runs over verified HTTPS with an ephemeral P-256 certificate in an owned private
directory. Trust is supplied only to each owned client; no global trust changes.

Each profile invokes the approved operation twice with distinct Unicode string
inputs retaining leading zeros. Checks verify actual native client identity,
operation description, decoded numeric result, actual HTTP status and distinct
correlation identifiers. The independent server must observe all eight expected
calls. Native wrong-hostname and public untrusted-CA tests follow healthy controls;
the server must receive no application calls from rejected connections. Foreign
endpoints and request transport overrides are rejected before I/O.

The native baseline uses the same reviewed upstream patches, native WSDL loader,
serializer, response decoder and explicit Axios HTTPS agent. It omits framework
immutable WSDL capture/import allowlists, complete input/scalar/fault policy,
bounded parser isolation, admission and lifecycle checks. This small
document/literal SOAP 1.1 workload does not establish SOAP 1.2, RPC, WS-Security
or arbitrary contract equivalence. Reports and SDK exports exclude payloads,
WSDL paths and endpoint data. Clients close before worker acknowledgment, and
the parent closes the server before removing its exact private directory.

`--verify` remains nonmeasured, with null resource fields, no latency samples
and `releaseGate: false`.

## Short supervised ReadStock comparison

Run measurements only in the owned disposable QEMU runner. Require an explicit
marker before certificate, fixture or evidence creation:

```sh
ARKENIVA_SOAP_BENCHMARK_DISPOSABLE=1 \
  pnpm --filter @arkenivajs/benchmark-foundation soap --smoke /private/soap-smoke
```

Every measured profile opts into `superviseProcessTree:true`. The same pinned
SOAP/Axios clients and explicit private CA are used in all four profiles; no
ambient trust variable, host trust-store change or insecure TLS override is
used. One `read-stock-verified-https` scenario runs 20 warmup callbacks followed
by 100 actual retained Tinybench latency samples. The first warmup callback
opens a new owned lease; the remaining callbacks reuse that lease while each
performs a real HTTPS request. At most one callback is active. The two fixed
Unicode inputs alternate, preserving leading zeros, and every decoded response
must be exactly numeric quantity 12 with actual HTTP status 200. There is no
cached SOAP result or fabricated timing sample.

The independent native parent server checks the exact decoded sku, encodes the
response through its conformance WSDL and independently decodes the outgoing XML
to require the exact quantity 12 result. Known request/response XML byte counts
come from the actual HTTP body streams; they are neither full TLS wire bytes nor
billed network traffic. Request and response bodies are each bounded to 4096 bytes,
with at most four live sockets/requests and 512 parent receipts. Workers retain
at most 128 private receipt/correlation IDs, close the workload lease before
completion and clear private receipt collections after computing their aggregate
integrity proof. Parent capture requires zero pending requests or sockets before
protocol evidence is accepted, then removes its exact private fixture directory.

The public `SoapResult.correlationId` is a local call identifier and is not
transmitted by the existing contract. Each worker verifies that its local IDs
are distinct. Separately, the fixture generates one random
`x-owned-soap-receipt` HTTP response header per actual decoded request. The worker
checks this header and computes an aggregate SHA256 integrity digest over the
ordered private server receipts, input choices and numeric outputs. The parent
compares that digest with its own independently captured sequence, partitioned
by actual per-profile call counts. This explicitly proves request/response
receipt correspondence; it does not pretend that the server saw the framework's
local correlation IDs. No raw IDs, XML, payloads, paths or endpoints enter the
reports or SDK exports. Server receipt values are added to the parent's dynamic
privacy checks before each SDK export/report is inspected. The aggregate digest
is a private benchmark integrity proof, never a telemetry attribute.

Completion requires actual started/successful callbacks equal to measured
samples plus warmup, distinct local and server receipts, balanced exact inputs,
zero active callbacks and zero owned workload leases. Parent decoded calls and
responses must match all actual receipts, including the initial two-call
verification corpus outside the samples. A normal four-profile smoke observes
488 requests/responses: 400 measured calls, 80 warmup calls and eight verification
calls. Existing native-client identity, approved operation, wrong-hostname,
untrusted-CA and endpoint/transport negative cases remain intact.

`resource` keeps measured-window comparison-worker CPU/RSS, heap, GC and
event-loop observations. Separate `processTreeResource` has
`scope: whole-supervised-lifecycle`: CPU includes the Node bridge, comparison
worker, its parser worker threads and any waited native descendants across
startup, verification, warmup, sampling, export, cleanup and exit. Whole-lifecycle
CPU must not be substituted for measured-window CPU/request numbers. The Python
observer, parent SOAP server/parser, collector and OpenSSL certificate setup are
excluded. All profiles require complete accessible descendant/RSS observations,
nontruncated discovery, positive bounded sampling rounds, all children waited
and zero remaining owned processes. Vanished short-lived observations and actual
sampling gaps remain explicit.

Sampled summed RSS is non-atomic, can miss short peaks and counts shared pages
once per observed process. It is not PSS or unique physical RAM; largest
single-process RSS remains separate. The existing 256 MiB comparison-worker
old-space ceiling, native parser 96 MiB worker-thread ceiling, operation timeouts
and 30-second supervised profile deadline remain unchanged. STANDARD and DETAILED
both use the shared helper's diagnostic trace sampling ratio 1, so STANDARD here
does not represent normal production sampling.

This small valid document/literal SOAP 1.1 corpus does not establish full
hostile-input policy equivalence, SOAP 1.2/RPC/WS-Security coverage, server CPU/RAM
cost, stable throughput, calibrated release budgets or confidence intervals.
Normative long warmup/steady trials, five paired repetitions and one-hour soak
remain separate and deferred. Unsupported full campaigns and unmarked smoke
are rejected before evidence creation; only the explicitly marked integration
case performs measured traffic.
