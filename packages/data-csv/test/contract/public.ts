// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createCsvService, dataCsvPlugin } from '../../dist/index.js';
import type { CsvService, CsvRecord } from '../../dist/index.js';

/** Compile public signatures and negative fixtures without pulling data. */
export function publicContract(csv: CsvService, row: CsvRecord) {
  const settings = { defaults: {}, policy: { maxConcurrent: 1, timeoutMs: 1000 } };
  createCsvService(settings);
  dataCsvPlugin(settings);
  // @ts-expect-error Only explicit UTF-8 input is supported.
  csv.parse(new Uint8Array(), { encoding: 'latin1' });
  // @ts-expect-error Records retain strings without implicit numeric coercion.
  csv.stringify([{ fields: [1], rowIndex: 1 }]);
  // @ts-expect-error Configuration requires finite runtime policy.
  dataCsvPlugin({ defaults: {} });
  // @ts-expect-error Returned record metadata is readonly.
  row.rowIndex = 2;
  return csv.validate(row, { columns: ['id'] });
}
