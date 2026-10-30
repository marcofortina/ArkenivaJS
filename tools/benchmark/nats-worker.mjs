// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { messagingPlugin } from '@arkenivajs/messaging';
import { runPureWorker } from './pure-worker.mjs';
import { nativeNats, natsConnection, verifyNats } from './nats-workload.mjs';

runPureWorker({
  name: 'nats',
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
    };
  },
  verify: verifyNats,
  close: (service) => service?.close(),
});
