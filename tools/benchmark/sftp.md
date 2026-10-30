<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Native SFTP and SSH server comparison

Build the workspace and use private metadata from the owned
[OpenSSH fixture](../../packages/sftp/test/fixtures/prepare.py):

```sh
ARKENIVA_SFTP_FIXTURE=/private/sftp/runtime.json \
  pnpm --filter @arkenivajs/benchmark-foundation sftp --verify /private/sftp-verification
```

The fixture must identify its loopback server and approved test directory.
Private key material enters child IPC, never arguments, environment, logs or
reports. Native ssh2-sftp-client and the public SFTP/SSH plugin verify the pinned
host key before authenticating in four isolated profiles. A healthy-server
negative test independently proves incorrect-pin rejection in both adapters.

Each profile uploads a fresh one-shot source to an exclusive random test path,
checks actual remote size, renames to an absent destination, downloads through
awaited callbacks and checks the actual SHA256 and exact bytes. An allowed
`printf` command must preserve literal quote/shell characters using the pinned
native quoting library; output is observed before channel close acknowledgement.
No command, file content, key, account, fingerprint or path reaches SDK exports.

Both test paths must be absent before starting. Cleanup removes only those two
owned paths. After all profiles, an independent authenticated client must confirm
their absence before `protocol-observation.json` can report zero residual files.
Renaming uses standard absent-destination semantics; its acknowledgement does
not establish atomic replacement or durable business publication.

The valid-corpus baseline shares SDK streams, native quoting and host-key checks.
Framework path/metadata policy, bounded admission, cancellation and lifecycle
add work and are not duplicated in full. `--verify` preserves those checks without
latency/resource samples and with `releaseGate: false`.

## Explicit bounded download smoke

Run actual measurements only in the owned disposable VM or disposable CI runner:

```sh
ARKENIVA_SFTP_FIXTURE=/private/sftp/runtime.json \
ARKENIVA_SFTP_BENCHMARK_DISPOSABLE=1 \
  pnpm --filter @arkenivajs/benchmark-foundation sftp --smoke /private/sftp-smoke
```

Unmarked smoke and unsupported `--full` are refused before fixture reads or
evidence creation. Four isolated profiles each execute one real 64 KiB download
scenario with 20 warmup callbacks and 100 measured callbacks. The actual Tinybench
latency samples are retained in milliseconds; warmup samples are excluded.
Chronological first-byte, total elapsed time, actual transferred bytes and
destination callback/chunk counters are retained separately, with explicit
warmup/measured phases. The two arrays do not imply sample-by-sample ordering.
Each timed callback awaits the complete public transfer receipt and verifies
every delivered byte, its SHA256 and receipt count. Consumer equality/hash work
is part of latency. Per-transfer byte throughput uses actual bytes and stream
duration, rather than only completed request counts.

Before creating measured callbacks, every profile applies the same documented
upstream `ssh2` `Client.setNoDelay(true)` through the trusted native escape hatch
and verifies that it returns that real client. This explicit smoke-only TCP
configuration disables Nagle's algorithm; it changes neither authentication nor
the wrapper's per-call ancestor `lstat`/`realPath` security checks. Verify-only
behavior and defaults are unchanged. A prior default-socket smoke exceeded the
unchanged 30-second whole-profile budget and remains preserved as a failure.
A separate two-call default-then-tuned diagnostic on the same client/path showed
a shorter tuned call; one ordered pair cannot isolate order/cache/environment
effects or establish a calibrated causal estimate. The smoke describes this
common tuned configuration, not default application socket performance.

The parent prepares two exclusive random owned files, 64 KiB and 256 KiB, through
the same approved pinned SDK before starting profiles. An independent native
client stats and reads both files before and after the comparison, checking exact
bytes and digest and acknowledging native handle closure. These uploads and
readbacks are outside timing. Cleanup deletes only the exact two prepared paths;
the existing `.part`/`.ready` verification paths must also be absent. No recursive
directory cleanup or unrelated remote deletion is performed. The report exposes
counts and integrity results, never keys, account names, pinned fingerprints,
remote paths or file contents. The corpus consists of SHA256 blocks of a synthetic
fixture marker and byte offset; it is not customer data.

Each profile also runs a separate 256 KiB pressure probe after sampling. The real
destination callback is held unresolved. Only during this probe, a temporary
wrapper around the trusted native client's `createReadStream` captures the actual
returned stream, forwarding the original receiver, arguments and result without
changing stream options, producer scheduling or the SSH/SFTP parser. The original
method descriptor is restored even on failure. No `data` listener is attached.
Passive observations use Node `readableLength` and the pinned ssh2 ReadStream's
`bytesRead`/`isClosed` fields. The SDK byte counter must reach a stable nonempty
queue **before EOF**, stay unchanged throughout a further approximately 50 ms
consumer pause, and then resume to the complete exact byte count and digest.
The destination remains single-flight, the transfer cannot settle while held,
and the actual native handle must close. A subsequent small healthy transfer
proves the managed profile is usable. Missing pre-EOF plateau is a failure;
limits are never raised to manufacture a result.

This establishes only destination-callback backpressure and the observed client
SDK readable's read-ahead plateau. It does **not** establish pressure or an exact
buffer peak inside the remote SSH server, socket, cipher or opaque SDK internals.
`peakObservedSdkReadableQueueBytes` is a passively sampled queue observation;
`opaqueSshSocketServerBufferBytes` stays `null` and
`remoteProducerPressureEstablished` stays false. The pause is an observation
fixture, not a new production latency requirement. The unchanged benchmark policy
still caps each direction at 262144 bytes, concurrency at two and operations at
10 seconds. Upload timing and a full remote-producer/buffer pressure measurement
remain explicitly unsupported.

Supervised lifecycle CPU includes the owned Node client/bridge and any native
descendants across startup, verification, warmup, measurement, pressure probe,
export and cleanup. Every profile requires complete descendant/RSS discovery,
physical child waits and zero remaining owned processes. Sampled RSS sums may
double count shared pages and miss brief peaks; they are not exact peak RAM.
The ordinary worker resource window covers warmup and measured calls, excluding
the later probe. The Python observer, parent/collector and external OpenSSH
server/container CPU/RSS are excluded; a configured server quota is not a measured
server resource cost. STANDARD and DETAILED both force trace sampling to one for
this diagnostic comparison, rather than normal production sampling.

This is a short valid-corpus component smoke with `measured: true` and
`releaseGate: false`. It does not establish full framework policy equivalence,
calibrated throughput/memory or instrumentation budgets, remote durability,
atomic publication or exactly-once transfer. Performance budgets, five repeated
trials and a one-hour soak remain separate.
