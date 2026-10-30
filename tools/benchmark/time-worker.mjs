// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureWorker } from './pure-worker.mjs';
import { nativeTime, timeSettings, verifyTime, timeWorkload } from './time-workload.mjs';
const originalZone = process.env.TZ;
process.once('beforeExit', () => assert.equal(process.env.TZ, originalZone));
runPureWorker({
  name: 'time',
  iterations: 1000,
  warmupIterations: 100,
  native: nativeTime,
  async framework() {
    const { dataTimePlugin, TIME_CAPABILITY } = await import('@arkenivajs/data-time');
    return { plugin: dataTimePlugin(timeSettings), key: TIME_CAPABILITY };
  },
  verify(service, fixture) {
    const result = verifyTime(service, fixture);
    assert.equal(process.env.TZ, originalZone);
    return { ...result, processZoneUnchanged: true };
  },
  workload: timeWorkload,
});
