<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# SFTP and SSH consumer

This consumer imports only public package exports, uploads a binary stream,
downloads it with backpressure, compares checksums, atomically publishes through
the real POSIX rename extension and runs a trusted command ID. It requires an
owned disposable OpenSSH fixture and leaves a uniquely named `.ready` file for
inspection until fixture teardown.

Run `pnpm --filter '@arkenivajs/example-sftp...' build`, then
`pnpm --filter @arkenivajs/example-sftp test`. For live verification, set
`ARKENIVA_SFTP_FIXTURE` to private external metadata and run
`pnpm --filter @arkenivajs/example-sftp test:integration`. Verify the installed
archive boundary with `pnpm test:packed:examples --integration sftp`.

Inside the owned integration VM or disposable CI runner, build
`docker build --tag arkenivajs-owned-sftp:r1 packages/sftp/test/fixtures` and run
`python3 packages/sftp/test/fixtures/prepare.py`. Its sole output is the private
runtime metadata path. Pass that path as `ARKENIVA_SFTP_FIXTURE`; it names the
trusted host, port, username, private key file, public pins and approved root.
The fixture creates fresh keys, pins the locally created host public key before
authentication, uses a read-only container image and finite tmpfs/resources, and
never learns host trust from the network. Do not run local service containers on
the laptop. Teardown with
`python3 packages/sftp/test/fixtures/teardown.py "$ARKENIVA_SFTP_FIXTURE"`.

Production applications supply a secure secret provider and deployment-owned
profiles. Do not expose fixture metadata, generic native calls or command
catalogs as application request inputs. See the complete
[package reference](../../packages/sftp/README.md) for bounds, concurrency,
native narrowing, server-side filesystem race limitations and unknown outcomes.
