// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { pathToFileURL } from 'node:url';
import { createApplication } from '@arkenivajs/core';
import { dataXlsxPlugin, XLSX_CAPABILITY } from '@arkenivajs/data-xlsx';
import type { ExcelService, XlsxCell } from '@arkenivajs/data-xlsx';

/** Produce and read two worksheets through the public, application-owned capability. */
export async function runXlsxExample() {
  const app = await createApplication({
    service: { name: 'xlsx-example', version: '0.1.0', environment: 'test' },
    plugins: [
      dataXlsxPlugin({
        defaults: {
          maxSheets: 2,
          maxRowsPerSheet: 1000,
          maxCells: 10000,
          maxUncompressedBytes: 1048576,
          formulaPolicy: 'preserve',
        },
        policy: {
          maxConcurrent: 1,
          timeoutMs: 10000,
          maxInputBytes: 1048576,
          maxOutputBytes: 1048576,
        },
      }),
    ],
  });
  try {
    await app.start();
    const excel = app.resolve<ExcelService>(XLSX_CAPABILITY),
      writer = excel.create(),
      sales = writer.addSheet('Sales'),
      dates = writer.addSheet('Dates');
    await sales.addRows([
      ['id', 'description', 'amount'],
      [
        '001',
        'Caffè 🦊 東京',
        {
          value: 123.45,
          style: {
            numberFormat: '#,##0.00',
            fontName: 'Arial',
            fontColorHex: '#112233',
            bold: true,
          },
        },
      ],
      [null, '=untrusted', { formula: '1+1', cachedValue: 2 }],
    ]);
    await dates.addRows([[new Date('2026-10-27T00:00:00Z')]]);
    const chunks: Buffer[] = [];
    const receipt = await writer.write(async (chunk) => {
      chunks.push(Buffer.from(chunk));
    });
    const reader = await excel.open(Buffer.concat(chunks));
    const counts: number[] = [],
      first: XlsxCell[] = [];
    try {
      for (const name of reader.sheetNames) {
        let count = 0;
        for await (const row of reader.rows(name)) {
          count++;
          if (name === 'Sales' && count === 2) first.push(...row.cells);
        }
        counts.push(count);
      }
    } finally {
      await reader.close();
    }
    return { receipt, names: ['Sales', 'Dates'], counts, sample: first };
  } finally {
    await app.stop();
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  console.log(JSON.stringify(await runXlsxExample()));
