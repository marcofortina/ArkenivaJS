<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Managed SFTP and SSH

`@arkenivajs/sftp` supplies explicit `sftpPlugin`, `SFTP_CAPABILITY` and
`SSH_CAPABILITY`. The native implementations are ssh2-sftp-client 12.1.1,
ssh2 1.17.0 and shell-quote 1.12.0. There is no custom SSH protocol,
cryptography or command escaping implementation. This local functional increment
has no production certification or published package claim.

```ts
import { sftpPlugin, SFTP_CAPABILITY } from '@arkenivajs/sftp';
import type { SftpService, SecretProvider } from '@arkenivajs/sftp';

export function partnerPlugin(secretProvider: SecretProvider, hostPin: string) {
  return sftpPlugin({
    connections: [
      {
        name: 'partner',
        host: 'files.example.test',
        port: 22,
        username: 'transfer',
        privateKeyRef: 'secrets://partner/private-key',
        knownHostSha256: [hostPin],
        allowedRemoteRoots: ['/incoming'],
      },
    ],
    secretProvider,
    policy: {
      maxConcurrent: 2,
      timeoutMs: 10000,
      maxInputBytes: 67108864,
      maxOutputBytes: 67108864,
    },
  });
}
export async function publish(sftp: SftpService, source: AsyncIterable<Uint8Array>) {
  const receipt = await sftp.upload('partner', source, '/incoming/report.part');
  const publication = await sftp.rename('partner', receipt.remotePath, '/incoming/report.ready', {
    overwrite: 'replace',
    requireAtomic: true,
  });
  return { receipt, publication, capability: SFTP_CAPABILITY };
}
```

Register the plugin before application startup. After `app.start()`, resolve
`app.resolve<SftpService>(SFTP_CAPABILITY)` and the separate `SshService` using
`SSH_CAPABILITY`. Initialization authenticates all named profiles before READY;
factories and imports perform no provider or network I/O. Application shutdown
aborts work and acknowledges physical socket closure. The plugin owns clients.

## Deployment trust and bounds

Profiles are trusted deployment configuration, never request input. A profile has
`name`, `host`, `port`, `username`, `privateKeyRef`, `knownHostSha256` and
`allowedRemoteRoots`. Pins are OpenSSH `SHA256:` fingerprints of the raw public
host key. Unknown keys fail `EK_SFTP_HOSTKEY` before authentication. Multiple pins
permit deliberate host-key rotation. There is no trust-on-first-use, password,
agent forwarding, keyboard-interactive authentication or debug callback.

`secretProvider.get(reference, options)` returns owned secret-provider bytes,
nonempty `keyVersion` and optional future ISO expiry. Private keys are limited to
64 KiB and copied for the handshake; the owned copy is erased afterwards. Provider
buffers are untouched. The native client necessarily retains parsed key material
while authenticated. Credential expiry closes its session. Production and
development application environments reject inherited `usage: 'test-only'`
provider markers. Do not put keys in settings, files in this repository, logs or
telemetry. The provider receives the operation signal and bounded remaining time.

There are 1–16 profiles, 1–16 distinct pins and approved roots per profile.
`maxConcurrent` is 1–8 operations globally, with one operation per profile and no
waiting queue. All configured profiles may retain idle authenticated connections.
`timeoutMs` is 1–120000 ms; per-call timeouts may only reduce it. Input/output
bounds default to 64 MiB each and accept 1 byte–1 TiB. Transfer `maxBytes` can only
reduce the applicable direction's bound. Streams process at most 1 MiB per source
chunk, with 64 KiB native stream buffers and awaited destination backpressure.
Directory listings have a 10000-entry bound and a cumulative path-byte/record
budget within `maxOutputBytes`; encrypted transport input additionally has a
finite input-plus-output budget with 4 MiB protocol overhead. This is not a
process RSS limit or a guarantee against hostile native library code.

Timeout or cancellation returns promptly while uncooperative provider, iterator
or destination promises continue to occupy admission. Drain waits for their real
settlement. A new call after a failed session may establish a fresh authenticated
connection; submitted mutations are never retried automatically. Admission
exhaustion and transfers fail `EK_SFTP_TRANSFER`; shutdown uses
`EK_RESOURCE_CLOSED`, cancellation `EK_ABORTED` and deadlines `EK_TIMEOUT`.

## Paths, publication and failure outcomes

Only absolute canonical POSIX paths under an approved remote root are accepted.
Every existing ancestor is checked with native `lstat` and `realpath`; links,
aliases, control characters, backslashes and root prefix lookalikes are rejected.
Listing reports link entries without following them. Deployments must also use a
server-side jail or permissions that prevent hostile concurrent filesystem
mutation. SFTP v3 has no general directory-handle-relative no-follow operation;
ancestor checks cannot eliminate races caused by another server-side actor.

Upload defaults to native exclusive creation (`overwrite: 'fail'`). Explicit
`'replace'` permits truncating an existing regular file. Upload is streamed, not
an atomic publication: interruption can leave a partial file, and cleanup never
deletes an ambiguously owned path. Choose a unique staging name and then rename
when publication must be atomic. Download supplies independent byte arrays and
awaits each destination. SHA-256 receipts describe transferred bytes; they are
not remote fsync, durable storage or atomicity guarantees.

Rename defaults to `overwrite: 'fail'`, `requireAtomic: false`. The native
negotiated `posix-rename@openssh.com` version 1 extension proves atomic replacement
only with explicit `overwrite: 'replace'`. Required atomic no-clobber and
replacement on servers without this extension fail `EK_UNSUPPORTED_CAPABILITY`
before modification. Standard no-clobber rename reports `not-guaranteed` and never
deletes the destination first. `replaced` records destination existence at the
preflight check; concurrent server-side actors require application coordination.
Failures after submission carry `details.outcome: 'unknown'`; do not infer rollback
or retry without reconciling remote state. Atomic rename does not imply fsync.

## Restricted commands and native access

`allowedCommands` maps a bounded command ID to a static absolute executable and
argument array. Complete-token `{name}` placeholders bind exact required string
arguments, each at most 4096 bytes, through native shell-quote. Unknown IDs,
unknown/missing arguments and oversized command lines fail before submission.
The catalog must contain safe application operations; never catalog an interpreter
with a caller-controlled program or expose a generic command endpoint to HTTP.
SSH stdin is closed, output is bounded jointly across stdout/stderr, and truncation
sets `truncated: true`, `exitCode: null`. A lost/cancelled acknowledgment cannot
report successful remote completion.

`native(connection): unknown` exposes the actual approved library instance only
after READY. Trusted application code imports its native types and deliberately
narrows it. ArkenivaJS retains connection ownership, host pinning and credential
configuration. Direct native reconnect/end calls and low-level reconnect calls
fail at runtime; the underlying instance identity is preserved. Native file calls
are unsupported wrapper operations: the application
must enforce authorization, tenant separation, size bounds, instrumentation and
coordination with managed operations. Do not reconnect or close a managed client,
replace its configuration or use a stale handle after a failure.

Diagnostics contain fixed operation/outcome labels, duration, actual transferred
bytes and active counts. No hostname, path, username, argument, command output,
key, secret version, raw driver error or credential is included.

## Verification and dependency review

See the [runnable consumer](../../examples/sftp/README.md). Unit tests use the
official ssh2 server API for host spoofing, absent rename extensions, permission
failure, safe quoting, output truncation and retained cancellation ownership.
Integration tests require `ARKENIVA_SFTP_FIXTURE`, exercise real OpenSSH, and never
silently skip missing infrastructure. Private fixture metadata stays outside the
repository. CI builds the pinned signed-snapshot Debian OpenSSH image on a
disposable runner; local service containers belong inside the owned QEMU VM.

The upstream SSH libraries remain pinned, with no enabled install hooks or custom
cryptography. Three exact metadata-only patches normalize existing legacy MIT
declarations for SPDX tools. See [third-party notices](THIRD_PARTY_NOTICES.md).
The native backend defaults provide the SSH algorithm policy; compression is
explicitly disabled. Encrypted private-key passphrases, general shell sessions,
agent authentication, remote fsync and cross-process publication locking are not
part of this public contract. Comparative performance campaigns remain pending.
