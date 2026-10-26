<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Native compression example

Build the framework, then run `pnpm --filter @arkenivajs/example-compression build`
and `pnpm --filter @arkenivajs/example-compression start`.
Expected output is `{"gzipRoundtrip":true,"zipEntries":2,"verifiedContents":true}`.
The example uses native GZIP, creates a ZIP with Unicode and empty-file contents,
reads verified entry data and closes its application. It writes no archive paths to
disk and contacts no external service.

Run `pnpm --filter @arkenivajs/example-compression test` for the public facade and CLI,
or `pnpm test:packed:examples --example compression` for a separate installation of
the packed public artifacts. See the [package guide](../../packages/data-compression/README.md)
for admission, streaming, limits, errors and integrity semantics. Performance and
remote compatibility are independent acceptance gates.
