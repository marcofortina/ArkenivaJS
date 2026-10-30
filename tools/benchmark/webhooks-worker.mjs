// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { webhooksPlugin, WEBHOOKS_CAPABILITY } from '@arkenivajs/webhooks';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runPureWorker } from './pure-worker.mjs';
import {
  nativeWebhooks,
  webhookSettings,
  verifyWebhooks,
  webhookWorkload,
  webhookObservations,
} from './webhooks-workload.mjs';

export const webhookAdapter = {
  name: 'webhooks',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  native: nativeWebhooks,
  framework: (fixture) => ({
    plugin: webhooksPlugin(webhookSettings(fixture)),
    key: WEBHOOKS_CAPABILITY,
  }),
  verify: verifyWebhooks,
  workload: webhookWorkload,
  complete: webhookObservations,
};

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  runPureWorker(webhookAdapter);
