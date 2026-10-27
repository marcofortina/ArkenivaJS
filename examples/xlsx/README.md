<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# XLSX worksheets

Run `pnpm --filter @arkenivajs/example-xlsx build` then `pnpm --filter @arkenivajs/example-xlsx test`. `pnpm --filter @arkenivajs/example-xlsx start` prints the small fixture's receipt and typed sample.

The project explicitly registers `dataXlsxPlugin`, writes Sales and Dates through native streaming workers, then reads them once in metadata order. It preserves leading-zero identifiers, Unicode, numeric styles and an explicit unexecuted formula cache. A local HTTP collector and real Pino/OTel plugins verify numeric workbook observations without exposing cell contents or sheet names. No remote service, system package or default temporary file is needed.

The collector in `src/main.ts` is intentionally restricted to the configured 1 MiB demonstration workbook. Applications should forward `write(target)` chunks with real destination backpressure and handle partial-write failures. Close every reader or writer in finally blocks; application shutdown also owns idle handles and native processes.

See the [API guide](../../packages/data-xlsx/README.md) for exact defaults, bounds, unsupported fidelity cases and explicit random-access staging. A pnpm deployment must retain the reviewed scoped ExcelJS UUID and unzipper overrides from the workspace. The [packed consumer verifier](../../scripts/check-packed-examples.mjs) tests the example against all actual package archives outside the workspace with those exact overrides.
