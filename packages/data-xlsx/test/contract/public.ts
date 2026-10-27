// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { dataXlsxPlugin, XLSX_CAPABILITY } from '../../dist/index.js';
import type { ExcelService, XlsxCell, XlsxRow, WorkbookReader } from '../../dist/index.js';
/** Public types expose workbook values and lifecycle without native engine declarations. */
export function contract(service: ExcelService, reader: WorkbookReader, row: XlsxRow) {
  dataXlsxPlugin({
    defaults: { formulaPolicy: 'reject', readMode: 'stream' },
    policy: { maxConcurrent: 1, timeoutMs: 1000 },
  });
  const writer = service.create(),
    sheet = writer.addSheet('Summary');
  const cells: readonly XlsxCell[] = [
    null,
    true,
    1,
    '001',
    new Date(),
    { formula: '1+1', cachedValue: 2 },
    { value: 1, style: { bold: true, horizontalAlignment: 'right' } },
  ];
  void sheet.addRows([cells]);
  // @ts-expect-error Styles expose only the reviewed public subset.
  sheet.addRows([[{ value: 1, style: { arbitraryCss: 'url(file:///private)' } }]]);
  // @ts-expect-error A native engine object cannot replace explicit input bytes.
  service.open({ nativeWorkbook: true });
  // @ts-expect-error Runtime policy is mandatory.
  dataXlsxPlugin({ defaults: {} });
  // @ts-expect-error Row metadata is readonly.
  row.rowIndex = 2;
  // @ts-expect-error Workbook metadata is readonly.
  reader.sheetNames.push('Injected');
  return XLSX_CAPABILITY;
}
