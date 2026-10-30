// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { dataXlsxPlugin, XLSX_CAPABILITY } from '@arkenivajs/data-xlsx';
import { runPureWorker } from './pure-worker.mjs';
import {
  xlsxSettings,
  nativeXlsx,
  verifyXlsx,
  prepareXlsxRead,
  xlsxReadWorkload,
  completeXlsxRead,
} from './xlsx-workload.mjs';

runPureWorker({
  name: 'xlsx',
  asynchronous: true,
  native: nativeXlsx,
  framework: () => ({ plugin: dataXlsxPlugin(xlsxSettings), key: XLSX_CAPABILITY }),
  async verify(service, fixture) {
    const result = await verifyXlsx(service, fixture);
    if (fixture.sampleReads) prepareXlsxRead(service, fixture);
    return result;
  },
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  workload: xlsxReadWorkload,
  complete: completeXlsxRead,
});
