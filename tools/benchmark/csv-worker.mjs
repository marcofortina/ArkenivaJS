// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureWorker } from './pure-worker.mjs';
import { nativeCsv, csvSettings, verifyCsv } from './csv-workload.mjs';
runPureWorker({
  name: 'csv',
  native: nativeCsv,
  async framework() {
    const { dataCsvPlugin, CSV_CAPABILITY } = await import('@arkenivajs/data-csv');
    return { plugin: dataCsvPlugin(csvSettings), key: CSV_CAPABILITY };
  },
  verify: verifyCsv,
});
