<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# HTTP comparison authentication audit parity

The HTTP comparison performs real signed-token verification in every protected
route. Its direct Pino baseline and framework profiles both emit an INFO
`Authentication completed` audit for each verification attempt, in addition to
one `HTTP request completed` row per completed request. The native audit contains
only the assigned request ID, the `verified` or `rejected` outcome and a bounded
error code for rejection. It never includes credentials or token claims.

Authentication verification precedes authorization. A valid signed identity can
have a `verified` audit and still receive HTTP 403 for its scope or tenant. The
benchmark separately counts actual authorized handler entries and actual SQL
calls. Missing, malformed, expired or wrong-audience tokens remain authentication
rejections. The public framework's security policy and audit logging are unchanged.

Before the CPU/profiler measurement begins, an empty write to the owned log
stream acknowledges earlier writes without emitting a row. Its actual completed
file-byte offset marks the warmup boundary. After the timed CPU and profiler
windows stop, another acknowledged boundary closes the measurement range. A
bounded file reader then counts actual rows and bytes, verifies INFO audit
fields and outcomes, and correlates each audit with its completed protected
request. Public requests cannot acquire an authentication audit. Duplicate,
missing or unrelated audit rows fail the comparison. The reader retains only assigned request IDs and
classification flags, within 1 GiB / two-million-row limits that include the
existing fixed-rate one-hour soak. This capacity check does not claim that a soak
was executed. Parsing happens outside the measured CPU/profiler windows; write acknowledgement is not fsync durability.

Each worker observation retains `logAudit`, independent verification/authorization
and SQL counters, and the existing logger transport counters. The real fixture
suite checks the original 13-request success/denial corpus in all four profiles,
including a valid signed token whose scope is denied. A separate signed invalid
tenant case proves that verification can be logged while SQL remains unexecuted;
a healthy request succeeds afterward. Raw bearer values remain absent from logs.

A comparison made before this parity change remains a historical observation of
its original workload. In particular, a native baseline with fewer audit events
cannot isolate adapter-only overhead against framework profiles that write more
rows. Preserve its raw data and disclose the mismatch; do not rewrite old
measurements or silently relabel them as a matched logging comparison. Additional
trace fields in STANDARD/DETAILED remain explicit instrumentation work. Pilot
results still provide no calibrated regression budget or release acceptance.
