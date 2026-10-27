<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Bounded XLSX workbooks

`@arkenivajs/data-xlsx` adapts ExcelJS 4.4.0 for typed worksheet values, controlled styles and formulas carried as data. Register `dataXlsxPlugin({defaults,policy})`, start the application and resolve `XLSX_CAPABILITY` as `ExcelService`. Imports and factories perform no file or process I/O. Operations require core READY; application drain cancels and joins owned workbooks.

```ts
const excel = app.resolve<ExcelService>(XLSX_CAPABILITY);
const writer = excel.create();
await writer.addSheet('Sales').addRows([
  ['id', 'amount'],
  ['001', { value: 123.45, style: { numberFormat: '#,##0.00', bold: true } }],
]);
const receipt = await writer.write(async (chunk) => {
  await destination.write(chunk);
});
await writer.close();
```

The target is an application callback returning `Promise<void>`, not a Node Writable. Bridge a Writable with its actual completion/error and backpressure signals. The executable [consumer](../../examples/xlsx/README.md) demonstrates a small bounded byte collector, application lifecycle and a typed roundtrip.

## Values and access modes

Cells accept strings, finite numbers, booleans, null, valid Dates or `{formula,cachedValue?}`; wrap a value as `{value,style?}` to attach formatting. Strings retain leading zeros, Unicode and formula-like prefixes as text. Dates use ExcelJS serial conversion and preserve supported UTC milliseconds in both 1900 and 1904 input epochs. New workbooks use the 1900 epoch. An absent formula cache and `cachedValue:null` share XLSX's absent-result representation and read as null. Formula strings omit the leading equals sign. No formula engine runs.

`formulaPolicy` defaults to `reject`; `preserve` returns formula text with its cached primitive value; `strip` returns only that cached value or null. External references, external-link functions, macros, embedded binary content, hyperlinks and external relationships are unsupported, including under strip mode. Never treat a cached formula result as newly calculated or trustworthy application data.

`open(source, options)` accepts a Uint8Array or one-shot AsyncIterable of Uint8Array. The default `readMode:'stream'` decodes native worksheet rows incrementally, traversing sheets exactly once in workbook metadata order. `sheetNames` is available after bounded archive inspection. A prior, repeated, skipped or concurrent sheet cursor fails with `EK_XLSX_UNSUPPORTED`. Concurrent `next()` calls are rejected without an implicit request queue. Returning early closes that workbook; open another explicitly if further access is required. A paused cursor retains its original deadline.

`readMode:'random-access'` allows sequential revisits to bounded byte input. A one-shot source requires explicit `temporaryStorage:{directory,maxBytes,cleanup:'always'}`. The directory must already exist, resolve without symlinks, belong to the current Unix user and deny group/other access. Temporary files use mode 0600 and exclusive no-follow creation; cleanup runs after successful opening, failure, cancellation and drain. Non-Unix staging is unsupported. There is no default temporary directory or transparent source replay.

Rows expose one-based `rowIndex` and dense cells through the last represented column; missing intermediate cells are null. Trailing unstyled blanks have no independent XLSX cell record and are not retained. Metadata, arrays and objects are frozen snapshots; Date objects are independent copies, not shared with native state.

## Controlled formatting and fidelity

Supported styles are `numberFormat`, `fontName`, `fontSize`, `bold`, `italic`, `fontColorHex`, `fillColorHex` and left/center/right `horizontalAlignment`. Colors normalize to `#RRGGBB`; opaque ARGB and untinted workbook theme colors are projected to that form. Native fonts' family/scheme metadata is outside this subset. Number formats remain strings; numeric currency values remain numbers. Formatting is data, never CSS, script or executable expressions.

Unknown public fields, ambiguous cell shapes, unsafe formatting, invalid colors and resource overflow fail explicitly. Rich text, error cells, ISO `t=d` cells, shared/array formulas, tinted/indexed colors, gradients, nontrivial borders and unsupported alignment/font effects fail unsupported rather than silently losing those features. Arbitrary workbook presentation, charts, images, pivot tables, conditional formatting and a full Excel object model are not exposed. This API is a controlled data-sheet projection and does not promise lossless file editing.

## Resource ownership

Policy requires positive integer `maxConcurrent` (1–8) and `timeoutMs` (1–120000). Compressed input defaults to 16 MiB, maximum 256 MiB; compressed output defaults to 32 MiB, maximum 256 MiB. No admission queue exists. Idle handles retain admission until closed; always close them in finally blocks. `create()` reserves a logical handle synchronously and starts its child only on asynchronous native work.

Defaults are 16 sheets (maximum 256), 100000 rows per sheet (maximum 1048576), 1000000 cells (maximum 10000000), 64 MiB measured uncompressed bytes (maximum 512 MiB), reject formulas and stream reading. Cell text is limited to 32767 UTF-16 units, formulas to 8192 UTF-8 bytes and rows to 16384 columns and 2 MiB projected bytes. Actual style records are bounded by `min(4096,maxCells+1)`; fonts/custom formats by `min(256,maxCells+1)`. Archive entry count, path uniqueness, XML nesting/attributes, declared and measured expansion, compression ratio, local/central headers and CRC are checked. OLE password-protected input and encrypted ZIP entries are rejected.

Each active workbook owns one Node child, one RPC slot and a 512 MiB V8 old-space budget. Child environment is whitelisted; application secrets, NODE_OPTIONS and NODE_DEBUG are not inherited. Node permission mode grants only module read roots and an explicitly staged file, without filesystem writes or child-process/worker permissions. This is process isolation with Node permissions, not an OS security sandbox or a 512 MiB total RSS guarantee. Finite byte limits, admission and native heap bounds all apply.

Compressed input is a finite captured snapshot. ZIP inspection precedes native row decoding; shared strings and metadata are bounded caches. The expanded worksheet row model is streamed. Native writing commits each row, accounts actual XML bytes and retains only bounded compressed output until `write(target)` supplies its destination. Multiple worksheets and shared strings can consume memory; the API does not claim constant memory regardless of workbook size. Target callbacks run sequentially with awaited backpressure. Source iterators are consumed once.

Abort/deadlines terminate owned children. Uncooperative source/target promises retain admission until actual settlement; application drain waits and may report its explicit shutdown deadline. Partial target writes cannot be rolled back; failures after a target attempt carry `details.outcome:'unknown'`. Successful write acknowledgement follows actual child exit. Public failures expose only `EK_XLSX_FORMAT`, `EK_XLSX_LIMIT`, `EK_XLSX_UNSUPPORTED` and common lifecycle/deadline errors, without native exception causes, paths or cell contents.

Optional Pino/OTel integration records fixed operations/outcomes, actual byte counts, decoded cells, first-row latency, cells per second and sampled worker RSS high-water measurements. RSS is sampled at IPC replies, not continuously. Workbook contents, sheet names and paths never enter diagnostics.

## Dependency compatibility

The pinned native engine is MIT licensed. Its CommonJS `uuid.v4` dependency uses a reviewed scoped override `exceljs@4.4.0>uuid:11.1.1`, retaining the same API while including upstream bounds-check fixes. The scoped `exceljs@4.4.0>unzipper:0.12.5` override retains native CommonJS ZIP parsing APIs and removes the legacy decoder's dependency on `buffers@0.1.1`, which has no declared license. Apply both exact overrides in a pnpm consumer deployment; the packed consumer verifier applies the reviewed workspace overrides. No UUID algorithm, ZIP decoder or ExcelJS runtime source is patched.

Saxes 6.0.0 has a declaration-only strict TypeScript compatibility patch under `compat/`; it constrains generic option aliases and explicitly permits undefined where upstream inheritance already does. The native JavaScript remains unchanged; [upstream notices](THIRD_PARTY_NOTICES.md) accompany the patch. Native streaming parser ports are private and checked against the pinned engine; public declarations do not expose ExcelJS, ZIP or XML types. Dependency maintenance, compatibility and advisory review remain release requirements.
