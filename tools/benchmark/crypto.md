# Native cryptography: four-profile compatibility smoke

This bounded exploratory runner compares direct native operations, the public
adapter, standard diagnostics and detailed diagnostics. It is not a calibrated
release gate, a production capacity measurement, five independent campaigns or a
one-hour soak. The command rejects `--full`; deferred campaigns never start
implicitly.

```sh
pnpm build
pnpm --filter @arkenivajs/benchmark-foundation crypto --smoke /private/existing-parent/new-crypto-report
```

Use a fresh normalized absolute output directory outside the repository, with an
existing parent. Symlinked parents resolve before the boundary check. Existing
output is never overwritten. The directory is 0700 and `report.json` is 0600.
No private key, raw corpus, secret fingerprint set or OTLP payload is persisted.

Each completed worker also leaves a private `*-observations.json` snapshot after
its metrics pass the material-leak check and before workload validation. These
snapshots remain explicitly `UNVERIFIED` and never establish acceptance. A failed
run can therefore retain its scheduling, saturation and completion counters;
only a completed validated `report.json` represents a passing smoke. Offered-load
failures are checked before provider-read equality, so skipped work cannot be
misreported as a provider retry. No load or privacy check is relaxed.

The parent clones one ephemeral corpus over closed IPC into four sequential
workers. The corpus has a 1 KiB payload, 32-byte AAD, AES/HMAC material,
Ed25519/P-256 PKCS#8 keys, SPKI public keys and runtime-allocated opaque versions.
Seed 137 controls profile order. Keys never enter environment variables or
command lines.

| Profile   | Operation path                                                                                                                     |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| BASELINE  | Direct `node:crypto`, the same borrowed provider reads, key imports, binary copying/clearing and documented envelope metadata/AAD. |
| FRAMEWORK | Public `CryptoService`, diagnostics disabled.                                                                                      |
| STANDARD  | Public service, actual SDK metrics and 10% root trace sampling.                                                                    |
| DETAILED  | Public service, metrics, full trace sampling and a span around each actual secret-provider read.                                   |

Eight scenarios cover encryption, authenticated decryption, HMAC generation and
comparison, Ed25519 signing/verification and P-256 signing/verification. Each has
five warmup calls, then 50 fixed offers at 50 operations/second with at most one
outstanding call. Missed schedules and saturated offers are counted without
queuing or catch-up bursts. The smoke requires all offers to complete without
errors or drops. Standard/detailed profiles must deliver actual traces and
metrics to the bounded loopback OTLP JSON receiver.

The native baseline intentionally does not emulate framework configuration,
lifecycle or admission checks. It measures added contract cost on valid fixture
operations, not an equivalent independent security implementation. Every profile
uses in-memory provider I/O. Verified HTTPS retrieval is covered by the separate
[runnable secret-provider example](../../examples/cryptography/README.md); it is
not represented as measured network key-management latency here.

Records include individual elapsed samples, p50/p95/p99/max, offered/completed
counts, scheduling lag, errors/drops, achieved operations/second and input
bytes/second. Result checks occur after the operation timer but remain in the
resource window. Per-profile CPU, sampled RSS/heap, observed GC, event-loop delay
and utilization, and provider reads are process aggregates including setup,
warmup, paced waits, SDK background export and flush. Memory uses 10 ms samples
and explicit boundaries; this cannot establish an exact transient peak. Reports
include hardware, Node/OpenSSL/FIPS state, source commit and dirty state.

Actual OTLP bodies are checked in memory against ephemeral fingerprints of keys,
input, AAD and observed cryptographic results. Leakage, exporter errors or
diagnostic drops fail the run. Observed JSON body bytes and repeated identical
bodies are reported; repeats are not asserted to be retries. Exact export retry
counts are unavailable and remain null. Parent receiver CPU, TCP wire overhead
and durable collector storage are not measured. Receiver acknowledgment does not
prove durable backend acceptance.

Workers have a 60-second watchdog and bounded SDK queues. The receiver accepts
eight concurrent requests, one MiB per body and 32 MiB overall. Unexpected worker
output fails the run; only fixed profile names and aggregate completion messages
reach stdout. Owned binary secrets, workers, providers and listeners are cleaned
up after execution. One repeat has no independent-repeat confidence interval:
those fields remain null and `releaseGate` remains false. A passing smoke does
not replace calibrated release evidence or remote CI.
