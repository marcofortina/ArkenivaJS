// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { dataXlsxPlugin, XLSX_CAPABILITY } from '@arkenivajs/data-xlsx';
import { runPureWorker } from './pure-worker.mjs';
import { xlsxSettings, nativeXlsx, verifyXlsx } from './xlsx-workload.mjs';

runPureWorker({
  name: 'xlsx',
  asynchronous: true,
  native: nativeXlsx,
  framework: () => ({ plugin: dataXlsxPlugin(xlsxSettings), key: XLSX_CAPABILITY }),
  verify: verifyXlsx,
  workload() {
    throw new Error(
      'XLSX sampling requires native child accounting and streaming first-row and buffer measurements',
    );
  },
});
