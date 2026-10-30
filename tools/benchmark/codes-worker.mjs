// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureWorker } from './pure-worker.mjs';
import { nativeCodes, codesSettings, verifyCodes } from './codes-workload.mjs';
runPureWorker({
  name: 'codes',
  native: nativeCodes,
  async framework() {
    const { dataCodesPlugin, CODES_CAPABILITY } = await import('@arkenivajs/data-barcodes');
    return { plugin: dataCodesPlugin(codesSettings), key: CODES_CAPABILITY };
  },
  verify: verifyCodes,
});
