<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native SMTP functional comparison

Build the workspace and choose a fresh absolute directory outside Git:

```sh
pnpm --filter @arkenivajs/benchmark-foundation mail --verify /private/mail-verification
```

Four isolated profiles perform actual transport verification and two messages
each through Nodemailer 10.2.1 and the public mail plugin. An ephemeral loopback
SMTP server requires STARTTLS and random disposable credentials. It independently
parses every received MIME message and verifies its text, filename and exact
streamed binary attachment. The protocol report requires eight accepted messages,
48 attachment bytes and authenticated TLS sessions. Acceptance is not delivery.

OpenSSL creates an ephemeral private certificate outside Git. Only the four
worker processes receive its path through Node startup trust configuration.
No system trust or parent environment changes occur. The server, private key,
certificate and directory are removed on success or failure. No mail is forwarded.
The fixture and native baseline use the already pinned smtp-server 3.21.1 and
mailparser 3.12.4. OpenSSL must be available for this local verification.

`--verify` keeps `measured: false`, null resources, no timing samples and
`releaseGate: false`. Actual standard/detailed exports must contain no
credentials, recipient addresses, message text or attachment filename.

## Short SMTP submission comparison

Run measurements only inside the owned disposable QEMU runner:

```sh
ARKENIVA_MAIL_BENCHMARK_DISPOSABLE=1 \
  pnpm --filter @arkenivajs/benchmark-foundation mail --smoke /private/mail-smoke
```

The explicit marker is required before certificate, fixture or report creation.
Unsupported full campaigns are rejected. The same four isolated profiles each
run one `smtp-accepted-streamed-attachment` scenario: 20 warmup callbacks and
100 actual retained Tinybench latency samples. Every callback creates a fresh
single-pass stream containing the same six binary bytes and waits for the real
SMTP acceptance response. At most one callback is active. Both native and
framework clients retain their identical one-connection pool, 100-message pool
recycling limit and zero requeues. Counts do not assume that one socket can
carry the entire workload without recycling.

The independent parent SMTP server verifies STARTTLS and authentication, exact
SMTP envelope sender/recipient, MIME sender/recipient, subject, text with only
the MIME terminal line ending normalized, filename and binary attachment. It
accepts only after MIME verification. Every captured Message-ID must be unique.
The worker keeps at most 128 private receipt IDs and the parent at most 512;
individual IDs never appear in evidence. Each worker computes an aggregate
SHA256 integrity digest over its ordered private IDs. The parent partitions its
independently captured private IDs by actual per-profile receipt counts and
checks the digests. This is a private benchmark integrity proof, never a
telemetry attribute, message identifier or delivery acknowledgment.

Actual callback counts must equal retained measured samples plus warmup. Parent
capture totals for accepted messages, envelope recipients, MIME recipients and
attachment bytes must match actual worker receipts, including the initial
verification corpus outside the samples. A normal four-profile smoke captures
488 messages and 2928 binary attachment bytes: 400 measured submissions,
80 warmup submissions and eight initial verification messages. These are
checked observations derived from callbacks and receipts, not fabricated timing
or delivery results.

Storage is bounded to 64 KiB per MIME body, four live SMTP clients/parser jobs,
512 parent IDs and 128 worker IDs. Raw MIME and IDs stay private and are removed
on cleanup. The parent waits for zero live sessions and parser work, equal
opened/closed connection counts and no failed MIME validation before writing
protocol evidence. The fixture is nonforwarding and is removed on success or
failure. Existing untrusted-root and authentication/privacy checks are retained.
The new measured integration case runs only with the explicit smoke marker;
CPU-only helper/refusal tests contain no SMTP connection or measurement.

Latency includes actual SMTP acceptance after the external server's MIME
validation. Nodemailer and framework MIME/attachment work run in the measured
client process; there is no hidden native worker child. CPU/RSS, heap, GC and
event-loop observations cover that client process during warmup and sampling.
They exclude the parent SMTP server, external MIME parser, server socket costs
and certificate setup. The shared helper retains its 256 MiB worker old-space
limit, 30-second per-profile deadline and bounded collector. STANDARD and
DETAILED both explicitly use diagnostic trace sampling ratio 1; STANDARD does
not represent normal production sampling.

SMTP acceptance is not recipient delivery or exactly-once submission. The bare
Nodemailer baseline still omits framework sender, byte, attachment, template and
secret-rotation policies, so this fixed valid-corpus comparison cannot establish
policy-equivalent overhead or production SMTP throughput. No complete
client/server pipeline resource cost, calibrated budget, confidence interval,
provider latency, durable recipient delivery, five paired repetitions or
one-hour soak is claimed. Normative long warmup/steady campaigns and the deferred
repeat/soak work remain separate.
