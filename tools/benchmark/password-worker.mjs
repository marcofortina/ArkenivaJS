// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureWorker } from './pure-worker.mjs';
import {
  nativePassword,
  passwordSettings,
  verifyPassword,
  preparePasswordSampling,
  passwordWorkload,
  completePassword,
  passwordIterations,
  passwordWarmupIterations,
} from './password-workload.mjs';
runPureWorker({
  name: 'password',
  native: nativePassword,
  async framework(fixture) {
    const { passwordPlugin, PASSWORD_CAPABILITY } = await import('@arkenivajs/security-password');
    return { plugin: passwordPlugin(passwordSettings(fixture)), key: PASSWORD_CAPABILITY };
  },
  async verify(service, fixture) {
    const result = await verifyPassword(service, fixture);
    if (fixture.sampleVerifies) preparePasswordSampling(service, fixture);
    return result;
  },
  asynchronous: true,
  iterations: passwordIterations,
  warmupIterations: passwordWarmupIterations,
  retainRawSamples: true,
  workload: passwordWorkload,
  complete: completePassword,
});
