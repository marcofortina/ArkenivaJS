# Streaming CSV and TSV

`@arkenivajs/data-csv` uses the prescribed `csv-parse@7.0.3` and
`csv-stringify@6.9.0`. Parsing uses the upstream streaming codec; writing calls
the upstream writer once per bounded record. Node streams provide backpressure,
cancellation and finite in-flight admission. The adapter does not implement a
CSV parser, coerce field types, buffer complete files or access the filesystem.

```typescript
import { createCsvService } from '@arkenivajs/data-csv';

const csv = createCsvService({
  defaults: { hasHeader: true, maxRows: 1000, maxRecordBytes: 65536 },
  policy: { maxConcurrent: 2, timeoutMs: 5000, maxInputBytes: 1048576 },
});

for await (const record of csv.parse(Buffer.from('id,note\n001,"hello, world"\n'))) {
  console.log(record.columns?.id); // 001: still text
  const result = csv.validate(record, { columns: ['id', 'note'] });
  if (!result.valid) throw new Error('Unexpected CSV columns');
}
```

| Option                      | Default and allowed range                                                         |
| --------------------------- | --------------------------------------------------------------------------------- |
| `delimiter`                 | `,`; one Unicode scalar other than CR/LF, including tab                           |
| `quote`                     | `"`; one scalar distinct from delimiter and CR/LF                                 |
| `escape`                    | Same as quote unless explicitly set; one scalar distinct from delimiter and CR/LF |
| `encoding`                  | Only `utf-8`                                                                      |
| `hasHeader`                 | `false`                                                                           |
| `inputBom`                  | `auto`; also `require` or `forbid`                                                |
| `outputBom`                 | `false`                                                                           |
| `escapeSpreadsheetFormulas` | `false`                                                                           |
| `maxColumns`                | 256; integer `1..10000`                                                           |
| `maxRecordBytes`            | 1 MiB; integer `1..16777216`                                                      |
| `maxRows`                   | 100000; integer `1..10000000`, excluding a header                                 |
| `maxTotalBytes`             | 64 MiB; integer `1..1073741824`                                                   |

Factory `defaults` and `policy` are both required and captured at construction.
Unknown fields, null settings, invalid scalar characters and zero/noninteger
limits fail with `EK_CONFIG_INVALID`. Operation options are validated at first
pull, before source data is read. They can override codec defaults within the
documented ranges; hard runtime-policy byte/deadline caps remain authoritative.

`parse(input,options?)` accepts bounded bytes or an asynchronous byte source and
returns immutable `CsvRecord` values. `rowIndex` starts at 1 and excludes the
header. `fields` are strings, including leading zeros and empty values; null and
implicit numeric/date conversion are unsupported. With `hasHeader:true`, the
first row defines exact case-sensitive column names and is not emitted. Duplicate
names, inconsistent widths and `__proto__`/`constructor`/`prototype` header keys
fail with `EK_CSV_SCHEMA`. Named records use frozen null-prototype dictionaries.
There is no automatic delimiter/header detection or silent malformed-row skipping.

Malformed quotes, invalid UTF-8 and BOM-policy violations fail with
`EK_CSV_PARSE`. The fatal UTF-8 decoder checks fragments without replacing bad
bytes. At most one leading BOM is accepted; a second leading BOM is rejected;
inner BOMs remain literal data. `require` rejects an absent BOM, including empty
input; `forbid` rejects a leading BOM. Raw record limits use upstream byte
positions, including quoting and record delimiters, rather than JavaScript
character counts. Native parser record bounds also prevent unbounded incomplete
fields. Size, row and column overflows use `EK_CSV_LIMIT`, with no truncation.
The native field callback also enforces column/raw-byte caps during parsing,
so delimiter-only records cannot accumulate an unbounded array before newline.

`stringify(rows,options?)` accepts a sync/async record iterable and emits bounded
UTF-8 chunks in source row order, with deterministic LF record delimiters. Each
record must have a positive safe-integer `rowIndex` and a consistent field count.
It does not buffer the complete document. With `hasHeader:true`, records must
provide consistent `columns`; the first record supplies the header. Parsed
records retain private immutable header-order metadata, so numeric-looking
headers also roundtrip in their original order across service instances. Manual
records use their column dictionary's own-key order and must align their `fields`
with it. Serializing/spreading a record can discard this ordering metadata: when
reconstructing it, explicitly align fields with the dictionary order. A missing
or inconsistent header fails instead of guessing or overwriting values.

`outputBom:true` emits a BOM once at stream start; input BOM options affect only
parsing. Record and total output limits count actual encoded UTF-8 bytes,
including quotes, delimiters, newlines and an output BOM. The per-record native
writer is bounded by the input record cap before encoding and the exact encoded
cap before emission. Empty headerless inputs/outputs are valid; an explicitly
required header must exist.

For exports opened in spreadsheets, enable `escapeSpreadsheetFormulas:true`.
The upstream apostrophe-prefix policy guards leading `=`, `+`, `-`, `@`, tab
and CR; the adapter additionally guards operators after leading Unicode
whitespace/control/format characters. This protection intentionally changes text
and is not automatically reversible. It applies to header and data cells only
during writing. Parsing never evaluates or silently rewrites formulas.

`validate(row,{columns})` is synchronous and returns the tagged
`{valid:true,value,errors:[]}` or `{valid:false,errors:[...]}` result. It validates
bounded shape, field count and ordered names without coercion or input mutation.
Rejected results have no value and do not include raw records in diagnostics.

Runtime policy requires `maxConcurrent:1..1024` and `timeoutMs:1..120000`.
Optional `maxInputBytes`/`maxOutputBytes` accept integers `1..1073741824` and act
as hard caps in addition to codec limits. Parsing counts raw input bytes and
output field-payload bytes; object metadata is excluded from the byte counter.
Writing counts input field-payload bytes and actual encoded output bytes.
Admission has no pending queue. Per-call `timeoutMs` is positive and can only
shorten the deployment deadline. `signal` must be a native AbortSignal; private
abort reasons and upstream diagnostics never enter public errors.
Monotonic checks reject late results even before a timer callback can run.
Input batches and encoded row batches yield cooperatively to the event loop,
including sources that repeatedly produce empty chunks.

Always consume to completion or call iterator `return()`/cancel with a signal.
`EK_TIMEOUT`/`EK_ABORTED` abort the native pipeline. Uncooperative upstream
iterators may delay their own finalization; admission remains occupied until the
native pipeline actually settles. Output can be partial on failure: receiving a
prefix is not successful completion or an atomic destination write.

For application ownership, install `dataCsvPlugin(settings)` and resolve
`CSV_CAPABILITY` as `CsvService`. Application stop cancels active pipelines and
invalidates only that application's handle with `EK_RESOURCE_CLOSED`.
`createCsvService` is an independent factory without unrelated required plugins.
The [utilities example](../../examples/utilities/README.md) also runs against
packed artifacts. Performance and remote compatibility remain release gates.
