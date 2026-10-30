// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureWorker } from './pure-worker.mjs';
import { nativeCodes, codesSettings, verifyCodes, codesWorkload } from './codes-workload.mjs';
let active;
runPureWorker({
  name: 'codes',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  native: nativeCodes,
  async framework() {
    const { dataCodesPlugin, CODES_CAPABILITY } = await import('@arkenivajs/data-barcodes');
    return { plugin: dataCodesPlugin(codesSettings), key: CODES_CAPABILITY };
  },
  verify: verifyCodes,
  workload(service, fixture) {
    active = codesWorkload(service, fixture);
    return active.workload;
  },
  complete(_service, { measure, records }) {
    return measure ? active.complete(records) : undefined;
  },
});
