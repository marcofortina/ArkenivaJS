// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { amqpPlugin, AMQP_CAPABILITY } from '@arkenivajs/messaging-amqp';
import { runPureWorker } from './pure-worker.mjs';
import { amqpSettings, nativeAmqp, verifyAmqp } from './amqp-workload.mjs';

runPureWorker({
  name: 'amqp',
  native: nativeAmqp,
  framework: (fixture) => ({ plugin: amqpPlugin(amqpSettings(fixture)), key: AMQP_CAPABILITY }),
  verify: verifyAmqp,
  close: (service) => service?.close(),
});
