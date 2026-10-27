// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { options } from '../../dist/settings.js';
import { createWriter, openReader } from '../../dist/backend.js';
import { inspect } from '../../dist/archive.js';
import type { XlsxCell } from '../../dist/contracts.js';

const value = (cell: XlsxCell) =>
  cell && typeof cell === 'object' && !(cell instanceof Date) && 'value' in cell
    ? cell.value
    : cell;
test('Native XLSX streaming adapters preserve worksheets and typed values without native temp staging', async () => {
  const policy = options(),
    writer = createWriter(policy, 1048576);
  let reader: Awaited<ReturnType<typeof openReader>> | undefined;
  try {
    writer.addSheet('Sales');
    writer.addSheet('Dates');
    writer.addRows(0, [
      ['001', 12.5, true, null, 'étoile'],
      ['=untrusted', 'a&amp;b'],
    ]);
    writer.addRows(1, [[new Date('2026-01-01T00:00:00Z')]]);
    const result = await writer.finish();
    assert.equal(result.receipt.writtenRows, 3);
    const output = Buffer.concat(result.chunks),
      inspection = await inspect(output, policy);
    assert.equal(inspection.rows, 3);
    assert.equal(inspection.cells, 7);
    reader = await openReader(Buffer.from(output), policy);
    assert.deepEqual(reader.names, ['Sales', 'Dates']);
    const rows = [];
    for await (const row of reader.rows('Sales')) rows.push(row);
    assert.deepEqual(rows[0]!.cells.map(value), ['001', 12.5, true, null, 'étoile']);
    assert.deepEqual(rows[1]!.cells.map(value), ['=untrusted', 'a&amp;b']);
    const dates = [];
    for await (const row of reader.rows('Dates')) dates.push(row);
    assert.equal((value(dates[0]!.cells[0]!) as Date).toISOString(), '2026-01-01T00:00:00.000Z');
  } finally {
    reader?.close();
    writer.close();
  }
});
test('Native XLSX controlled styles roundtrip and binary output is reproducible within one runtime profile', async () => {
  const policy = options(),
    outputs: Buffer[] = [];
  for (let repeat = 0; repeat < 2; repeat++) {
    const writer = createWriter(policy, 1048576);
    let reader: Awaited<ReturnType<typeof openReader>> | undefined;
    try {
      writer.addSheet('Report');
      writer.addRows(0, [
        [
          {
            value: 123.45,
            style: {
              numberFormat: '#,##0.00',
              fontName: 'Arial',
              fontSize: 12,
              bold: true,
              italic: true,
              fontColorHex: '#112233',
              fillColorHex: '#AABBCC',
              horizontalAlignment: 'right',
            },
          },
        ],
      ]);
      const result = await writer.finish(),
        output = Buffer.concat(result.chunks);
      outputs.push(output);
      reader = await openReader(Buffer.from(output), policy);
      for await (const row of reader.rows('Report')) {
        const current = row.cells[0];
        assert.ok(current && typeof current === 'object' && 'style' in current);
        assert.equal(current.style?.numberFormat, '#,##0.00');
        assert.equal(current.style?.fontColorHex, '#112233');
        assert.equal(current.style?.fillColorHex, '#AABBCC');
      }
    } finally {
      reader?.close();
      writer.close();
    }
  }
  assert.deepEqual(outputs[0], outputs[1]);
});
