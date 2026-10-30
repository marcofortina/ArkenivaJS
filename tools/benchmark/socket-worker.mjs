// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { socketPlugin, SOCKET_CAPABILITY } from '@arkenivajs/socket';
import { runPureWorker } from './pure-worker.mjs';
import {
  nativeSocket,
  verifySocket,
  prepareSocketEcho,
  socketEchoWorkload,
  completeSocketEcho,
} from './socket-workload.mjs';

runPureWorker({
  name: 'socket',
  native: nativeSocket,
  framework: () => ({ plugin: socketPlugin(), key: SOCKET_CAPABILITY }),
  async verify(service, fixture) {
    const result = await verifySocket(service, fixture);
    if (fixture.sampleEcho) await prepareSocketEcho(service, fixture);
    return result;
  },
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  workload: socketEchoWorkload,
  complete: completeSocketEcho,
  close: (service) => service?.close(),
});
