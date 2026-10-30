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
add work and are not duplicated in full. Only `--verify` is supported, with no
latency/resource samples and `releaseGate: false`. Streaming sampling requires
first-byte, total duration, backpressure waits and peak-buffer observations.
Performance budgets, five repeated trials and a one-hour soak remain separate.
