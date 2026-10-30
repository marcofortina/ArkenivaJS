// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureWorker } from './pure-worker.mjs';
import { nativeCore, frameworkCore, verifyCore, coreWorkload } from './core-workload.mjs';

runPureWorker({
  name: 'core',
  retainRawSamples: true,
  iterations: 1000,
  warmupIterations: 100,
  native: nativeCore,
  framework: frameworkCore,
  verify: verifyCore,
  workload: coreWorkload,
  close: (service) => service.close(),
});
