// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { dataJsonPlugin, JSON_CAPABILITY } from '@arkenivajs/data-json';
import { runPureWorker } from './pure-worker.mjs';
import {
  jsonSettings,
  nativeJson,
  verifyJson,
  jsonWorkload,
  completeJsonWorkload,
  jsonIterations,
  jsonWarmupIterations,
} from './json-workload.mjs';

runPureWorker({
  name: 'json',
  native: nativeJson,
  framework: () => ({ plugin: dataJsonPlugin(jsonSettings()), key: JSON_CAPABILITY }),
  verify: verifyJson,
  iterations: jsonIterations,
  warmupIterations: jsonWarmupIterations,
  retainRawSamples: true,
  workload: jsonWorkload,
  complete: completeJsonWorkload,
});
