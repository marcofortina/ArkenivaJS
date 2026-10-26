<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Native QR and barcode example

Run `pnpm --filter @arkenivajs/example-barcodes build` and
`pnpm --filter @arkenivajs/example-barcodes start` after building the framework.
Expected output is `{"roundtrips":3,"svgGenerated":true}`. The program creates one
application-owned codec process, roundtrips QR with Unicode, CODE128 and EAN13,
generates SVG, then stops the application. It writes no files and follows no links.

`pnpm --filter @arkenivajs/example-barcodes test` verifies the public facade and
the executable's output/cleanup. `pnpm test:packed:examples --example barcodes`
rebuilds this example against packed public artifacts outside the workspace.
See the [package policy](../../packages/data-barcodes/README.md) for limits,
errors, native dependencies and decoding limitations. This is a functional fixture;
performance and remote architecture acceptance remain separate release gates.
