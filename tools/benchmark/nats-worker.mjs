// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { messagingPlugin } from '@arkenivajs/messaging';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runPureWorker } from './pure-worker.mjs';
import {
  nativeNats,
  natsConnection,
  verifyNats,
  natsWorkload,
  natsObservations,
  closeNatsWorkload,
} from './nats-workload.mjs';

export const natsAdapter = {
  name: 'nats',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  native: nativeNats,
  framework(fixture) {
    natsConnection(fixture);
    process.env.ARKENIVA_NATS_COMPARISON_URL = fixture.url;
    return {
      plugin: messagingPlugin({
        connectionStringEnv: 'ARKENIVA_NATS_COMPARISON_URL',
        onError: async () => {
          throw new Error('The owned NATS comparison error policy rejected a failure');
        },
      }),
      key: COMPONENTS.messaging,
      dispose: () => closeNatsWorkload(fixture),
    };
  },
  verify: verifyNats,
  workload: natsWorkload,
  complete: natsObservations,
  async close(service) {
    try {
      await closeNatsWorkload(service);
    } finally {
      await service?.close();
    }
  },
};

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  runPureWorker(natsAdapter);
