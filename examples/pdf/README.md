<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Searchable PDF documents

Run `pnpm --filter @arkenivajs/example-pdf build` then `pnpm --filter @arkenivajs/example-pdf test`. `pnpm --filter @arkenivajs/example-pdf start` prints typed metadata and extracted text from this small synthetic report.

The example explicitly registers `documentsPdfPlugin`, creates searchable text with Helvetica, adds rotated text to a copy and merges the original and edited pages. A local HTTP receiver and actual Pino/OTel plugins verify numeric size, native CPU, sampled RSS and throughput observations without exposing document contents. No external service or default temporary file is required.

The verified Linux runtime requires util-linux's `/usr/bin/prlimit`, which enforces the worker's data-allocation and core-dump policy. No host package installation is performed by the example. Native canvas support uses the dependency's shipped Node-API binary. The [API guide](../../packages/documents-pdf/README.md) explains exact byte/page/font bounds, standard versus embedded Unicode fonts, signature policy, supported formats and resource-isolation limits.

All operations run only while core is READY. The application owns cancellation and physical child completion. Signed and encrypted inputs require the documented failure handling; earlier inspection is never an authorization to rewrite a signed document. Production code remains responsible for identity/tenant authorization before exposing document operations or returned content.

Run `pnpm test:packed:examples --example pdf` to recompile and exercise the consumer against actual framework package archives outside the workspace.
