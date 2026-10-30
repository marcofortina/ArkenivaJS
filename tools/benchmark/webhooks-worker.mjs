// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { webhooksPlugin, WEBHOOKS_CAPABILITY } from '@arkenivajs/webhooks';
import { runPureWorker } from './pure-worker.mjs';
import { nativeWebhooks, webhookSettings, verifyWebhooks } from './webhooks-workload.mjs';

runPureWorker({
  name: 'webhooks',
  asynchronous: true,
  native: nativeWebhooks,
  framework: (fixture) => ({
    plugin: webhooksPlugin(webhookSettings(fixture)),
    key: WEBHOOKS_CAPABILITY,
  }),
  verify: verifyWebhooks,
  workload() {
    throw new Error('Durable webhook performance sampling requires an explicit paired workload');
  },
});
