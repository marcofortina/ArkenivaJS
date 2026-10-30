// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureWorker } from './pure-worker.mjs';
import { healthSettings, nativeHealth, verifyHealth, healthWorkload } from './health-workload.mjs';

runPureWorker({
  name: 'health',
  retainRawSamples: true,
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  native: nativeHealth,
  async framework(fixture) {
    const { healthPlugin } = await import('@arkenivajs/health');
    const { COMPONENTS } = await import('@arkenivajs/core');
    return { plugin: healthPlugin(healthSettings(fixture)), key: COMPONENTS.health };
  },
  verify: verifyHealth,
  workload: healthWorkload,
  close: (service) => service.close(),
});
