// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { realpathSync } from 'node:fs';
import { Readable } from 'node:stream';
import type { Duplex } from 'node:stream';
import { options } from '../../dist/settings.js';
import { createWriter, openReader } from '../../dist/backend.js';
import { inspect } from '../../dist/archive.js';
import type { XlsxCell } from '../../dist/contracts.js';
import ExcelJS from 'exceljs';
import type { Style } from 'exceljs';
import { KitError } from '@arkenivajs/core';

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

test('The reviewed CommonJS ZIP decoder preserves the native ExcelJS streaming entry API', async () => {
  const require = createRequire(import.meta.url),
    nativeRequire = createRequire(realpathSync(require.resolve('exceljs'))),
    upstream = nativeRequire('unzipper') as {
      Parse(options: { forceStream: true }): Duplex & AsyncIterable<Readable & { path: string }>;
    },
    writer = createWriter(options(), 1048576);
  try {
    writer.addSheet('Data');
    writer.addRows(0, [[1]]);
    const output = await writer.finish(),
      stream = Readable.from([Buffer.concat(output.chunks)]).pipe(
        upstream.Parse({ forceStream: true }),
      ),
      paths: string[] = [];
    for await (const entry of stream) {
      paths.push(entry.path);
      for await (const chunk of entry) assert.ok(Buffer.isBuffer(chunk));
    }
    assert.ok(paths.includes('xl/workbook.xml'));
    assert.ok(paths.includes('xl/worksheets/sheet1.xml'));
  } finally {
    writer.close();
  }
});

test('Native XLSX style projection fails explicitly for unsupported formatting instead of silently losing fidelity', async () => {
  const samples: Partial<Style>[] = [
    { font: { underline: true } },
    { font: { strike: true } },
    { alignment: { horizontal: 'justify' } },
    { alignment: { vertical: 'top' } },
    { alignment: { textRotation: 45 } },
    { border: { bottom: { style: 'thin' } } },
    { fill: { type: 'pattern', pattern: 'darkGrid' } },
    { fill: { type: 'pattern', pattern: 'solid', fgColor: { theme: 99 } } },
    { font: { color: { argb: '00112233' } } },
    {
      fill: {
        type: 'gradient',
        gradient: 'angle',
        degree: 45,
        stops: [
          { position: 0, color: { argb: 'FF000000' } },
          { position: 1, color: { argb: 'FFFFFFFF' } },
        ],
      },
    },
  ];
  for (const [index, presentation] of samples.entries()) {
    const workbook = new ExcelJS.Workbook();
    workbook.addWorksheet('Data').getCell('A1').value = 'Owned';
    workbook.getWorksheet('Data')!.getCell('A1').style = presentation;
    const reader = await openReader(Buffer.from(await workbook.xlsx.writeBuffer()), options());
    try {
      await assert.rejects(
        async () => {
          for await (const item of reader.rows('Data')) void item;
        },
        (error: unknown) => error instanceof KitError && error.code === 'EK_XLSX_UNSUPPORTED',
        `Native style boundary ${index}`,
      );
    } finally {
      reader.close();
    }
  }
});

test('Native XLSX writer preserves minimal explicit styles and nullable formula caches', async () => {
  const policy = options({ formulaPolicy: 'preserve' }),
    writer = createWriter(policy, 1048576);
  let reader: Awaited<ReturnType<typeof openReader>> | undefined;
  try {
    writer.addSheet('Data');
    writer.addRows(0, [
      [
        { value: 'plain', style: { horizontalAlignment: 'center' } },
        { value: 1, style: { bold: false, italic: false, fontSize: 10 } },
        { formula: '1', cachedValue: null },
        { formula: '2' },
      ],
    ]);
    const output = await writer.finish();
    reader = await openReader(Buffer.concat(output.chunks), policy);
    const rows = [];
    for await (const item of reader.rows('Data')) rows.push(item);
    assert.deepEqual(rows[0]!.cells.map(value), [
      'plain',
      1,
      { formula: '1', cachedValue: null },
      { formula: '2', cachedValue: null },
    ]);
    await assert.rejects(
      async () => {
        for await (const item of reader!.rows('Missing')) void item;
      },
      (error: unknown) => error instanceof KitError && error.code === 'EK_XLSX_UNSUPPORTED',
    );
  } finally {
    reader?.close();
    writer.close();
  }
});
