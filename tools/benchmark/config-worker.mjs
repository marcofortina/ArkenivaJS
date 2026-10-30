// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureWorker } from './pure-worker.mjs';
import { nativeConfig, configOptions, verifyConfig, configWorkload } from './config-workload.mjs';
runPureWorker({
  name: 'config',
  retainRawSamples: true,
  asynchronous: true,
  iterations: 1000,
  warmupIterations: 100,
  native: nativeConfig,
  async framework(fixture) {
    const { createConfig, configPlugin } = await import('@arkenivajs/config');
    const { COMPONENTS } = await import('@arkenivajs/core');
    const service = await createConfig(configOptions(fixture));
    return { plugin: configPlugin(service), key: COMPONENTS.config };
  },
  verify: verifyConfig,
  workload: configWorkload,
});
