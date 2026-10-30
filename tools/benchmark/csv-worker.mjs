// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runPureWorker } from './pure-worker.mjs';
import {
  nativeCsv,
  csvSettings,
  verifyCsv,
  csvWorkload,
  csvObservations,
} from './csv-workload.mjs';
export const csvAdapter = {
  name: 'csv',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  native: nativeCsv,
  async framework() {
    const { dataCsvPlugin, CSV_CAPABILITY } = await import('@arkenivajs/data-csv');
    return { plugin: dataCsvPlugin(csvSettings), key: CSV_CAPABILITY };
  },
  verify: verifyCsv,
  workload: csvWorkload,
  complete: csvObservations,
};

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  runPureWorker(csvAdapter);
