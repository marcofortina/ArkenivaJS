// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureWorker } from '../../pure-worker.mjs';

runPureWorker({
  name: 'counted-sync',
  native: () => ({ calls: 0 }),
  verify: (service) => {
    assert.equal(service.calls, 0);
    return { callsBeforeWorkload: service.calls };
  },
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  workload: (service) => ({ increment: () => ++service.calls }),
  complete: (service) => ({ actualCalls: service.calls }),
});
