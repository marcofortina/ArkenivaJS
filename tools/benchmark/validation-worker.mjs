// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureWorker } from './pure-worker.mjs';
import {
  nativeValidation,
  validationSettings,
  validationWorkload,
  verifyValidation,
} from './validation-workload.mjs';
runPureWorker({
  name: 'validation',
  retainRawSamples: true,
  native: nativeValidation,
  async framework() {
    const { dataValidationPlugin, VALIDATION_CAPABILITY } =
      await import('@arkenivajs/data-validation');
    return { plugin: dataValidationPlugin(validationSettings), key: VALIDATION_CAPABILITY };
  },
  verify: verifyValidation,
  workload: validationWorkload,
});
