<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Verified LDAPS protocol comparison

Build the workspace and use the private metadata emitted by the owned
[OpenLDAP fixture](../../packages/security-ldap/test/fixtures/prepare.py):

```sh
ARKENIVA_LDAP_FIXTURE=/private/ldap/runtime.json \
  pnpm --filter @arkenivajs/benchmark-foundation ldap --verify /private/ldap-verification
```

The fixture uses its owned loopback LDAPS endpoint on port 16389; its healthy
wrong-SAN endpoint on 16390 must reject verification. No host trust-store change
is made. Only private fixture metadata is read; passwords enter child IPC, never
child environment or arguments. Four isolated profiles use direct `ldapts`, the
public LDAP plugin, and actual standard/detailed SDK instrumentation.

Each profile performs a real service bind, projected user lookup, absent-user
and literal filter-injection lookups, then successful and incorrect-password
user binds. Equality filter values are bound through native BER objects. Fresh
service and user connections are never pooled together. Reports and exports
exclude usernames, DNs, passwords, endpoints and trust material.

The valid-corpus baseline uses the same SDK, CA/hostname checks and fresh-client
pattern. Additional framework work includes secret capture, native child process
isolation, IPC, bounded projections, admission and lifecycle. This comparison
does not establish equivalence of every hostile-input policy.

`--verify` remains nonmeasured, with null resource observations and
`releaseGate: false`; it does not start the supervisor.

## Short supervised LDAPS search comparison

Measurements run only inside the owned disposable QEMU fixture. Use the current
private metadata and require the explicit smoke marker before metadata access
or evidence creation:

```sh
ARKENIVA_LDAP_BENCHMARK_DISPOSABLE=1 \
ARKENIVA_LDAP_FIXTURE=/private/ldap/runtime.json \
  pnpm --filter @arkenivajs/benchmark-foundation ldap --smoke /private/ldap-smoke
```

The controller opts into `superviseProcessTree:true` for all four measured
profiles. There is no fallback to worker-only CPU/RSS accounting. Missing Linux
supervision facilities, incomplete descendant discovery/RSS access or unfinished
owned processes refuse acceptance. The [supervised comparison](supervised-comparison.md)
retains fixed limits, protected IPC, ownership-scoped cleanup and normal
non-supervised defaults for other callers. The CA PEM is explicit fixture data:
native `ldapts` receives `tlsOptions.ca`, and the framework's private secret
provider supplies the same CA to its native worker. No ambient trust variable,
`NODE_EXTRA_CA_CERTS`, host trust-store edit or insecure TLS override is used.

Each profile runs one sequential `verified-service-bind-and-user-search`
scenario with 20 warmup callbacks followed by 100 actual retained Tinybench
latency samples. Each callback performs a fresh authenticated service bind and
literal user lookup, and awaits native unbind/physical completion. The returned
DN, UID and exact uid/cn projection must match the private result obtained by the
initial independent native lookup. At most one callback is active; no result
cache is measured. After sampling, one fresh independent native LDAPS readback
must match that entry again. It remains outside the latency samples. Completion
requires exact actual started/successful callback counts equal to the raw sample
count plus warmup, one independent readback and zero active callbacks. These are
application callback counts, not invented directory wire/request counters.
Private entries, DNs, username, passwords, endpoints and CA data never enter
reports or SDK exports. Initial absent-user, filter-injection, incorrect-password
and wrong-hostname certificate cases remain intact.

`resource` retains measured-window worker-only CPU/RSS, GC and event-loop fields.
Separate `processTreeResource` observations have
`scope: whole-supervised-lifecycle`: user/system CPU includes the Node bridge,
comparison worker and every waited native descendant across startup,
verification, warmup, measurement, export, cleanup and exit. These lifecycle CPU
values must never be substituted for measured-window CPU/request numbers.
The Python observer, parent collector and external OpenLDAP server are excluded.
All profiles must have `allChildrenWaited: true`, zero remaining owned processes,
accessible descendant discovery/RSS reads, no truncated traversal and positive
bounded sampling rounds. Vanished short-lived reads and actual maximum sampling
gaps remain explicitly reported.

Sampled summed RSS is non-atomic, can miss brief peaks and counts shared resident
pages separately in every process; it is not PSS or unique physical RAM.
Largest single-process RSS remains a distinct Linux observation. All profiles
use the same resource method. The 256 MiB comparison-worker old-space ceiling,
64 MiB native-worker old-space ceiling, operation timeouts and 30-second
supervised profile deadline remain unchanged. STANDARD and DETAILED both use the
shared helper's diagnostic trace sampling ratio 1; STANDARD here does not
represent normal production sampling.

This fixed valid-corpus comparison does not establish complete policy-equivalent
wrapper overhead, server CPU/RAM cost, stable throughput, confidence intervals,
calibrated budgets or release acceptance. Group traversal, streamed search,
STARTTLS, Microsoft AD staging, normative long warmup/steady trials, five paired
repetitions and one-hour soak remain separate and deferred. The dedicated real
smoke integration case requires the explicit marker; ordinary unit checks make
no LDAP connection or performance measurement.
