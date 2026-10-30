// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { parse } from 'csv-parse';
import { stringify } from 'csv-stringify';

export const csvFixture = Object.freeze({ marker: 'owned-csv-fixture' });
export const csvSettings = Object.freeze({
  defaults: Object.freeze({}),
  policy: Object.freeze({ maxConcurrent: 1, timeoutMs: 5000 }),
});
export const csvFields = Object.freeze([
  Object.freeze(['001', csvFixture.marker, 'line\nnext', '"quoted"', 'λ😀']),
  Object.freeze(['002', 'comma,value', '', 'tab\tvalue', 'last']),
]);
export const csvRows = () => csvFields.map((fields, index) => ({ fields, rowIndex: index + 1 }));
export async function collectCsvBytes(input) {
  const chunks = [];
  for await (const chunk of input) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}
export async function collectCsvFields(input) {
  const rows = [];
  for await (const row of input) {
    assert.equal(row.rowIndex, rows.length + 1);
    assert.ok(row.fields.every((value) => typeof value === 'string'));
    rows.push([...row.fields]);
  }
  return rows;
}
/** Native stream adapters cover a fixed valid corpus without framework policy emulation. */
export function nativeCsv() {
  return {
    async *parse(input, options = {}) {
      const source = Readable.from(input instanceof Uint8Array ? [input] : input, {
          objectMode: false,
          highWaterMark: 16384,
        }),
        codec = parse({ delimiter: options.delimiter ?? ',', bom: true, cast: false }),
        task = pipeline(source, codec);
      void task.catch(() => undefined);
      let rowIndex = 0;
      try {
        for await (const fields of codec) yield { fields, rowIndex: ++rowIndex };
        await task;
      } finally {
        source.destroy();
        codec.destroy();
      }
    },
    async *stringify(rows, options = {}) {
      const source = Readable.from(
          (async function* () {
            for await (const row of rows) yield row.fields;
          })(),
        ),
        codec = stringify({
          delimiter: options.delimiter ?? ',',
          bom: options.outputBom ?? false,
          record_delimiter: '\n',
        }),
        task = pipeline(source, codec);
      void task.catch(() => undefined);
      try {
        for await (const chunk of codec) yield chunk;
        await task;
      } finally {
        source.destroy();
        codec.destroy();
      }
    },
  };
}
export async function verifyCsv(service) {
  for (const delimiter of [',', '\t', ';']) {
    const bytes = await collectCsvBytes(
        service.stringify(csvRows(), { delimiter, outputBom: true }),
      ),
      before = Buffer.from(bytes);
    assert.deepEqual([...bytes.subarray(0, 3)], [239, 187, 191]);
    let pulls = 0;
    const input = (async function* () {
      for (let index = 0; index < bytes.length; index++) {
        pulls++;
        yield bytes.subarray(index, index + 1);
      }
    })();
    assert.deepEqual(await collectCsvFields(service.parse(input, { delimiter })), csvFields);
    assert.equal(pulls, bytes.length);
    assert.deepEqual(bytes, before);
  }
  assert.deepEqual(await collectCsvFields(service.parse(new Uint8Array())), []);
  assert.equal((await collectCsvBytes(service.stringify([]))).length, 0);
  return { checkedDelimiters: 3, checkedRows: 6, completedStreams: true, textOnly: true };
}
