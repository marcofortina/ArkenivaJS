// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { amqpPlugin, AMQP_CAPABILITY } from '@arkenivajs/messaging-amqp';
import { runPureWorker } from './pure-worker.mjs';
import {
  amqpSettings,
  nativeAmqp,
  verifyAmqp,
  amqpWorkload,
  completeAmqpWorkload,
  amqpIterations,
  amqpWarmupIterations,
} from './amqp-workload.mjs';

runPureWorker({
  name: 'amqp',
  asynchronous: true,
  iterations: amqpIterations,
  warmupIterations: amqpWarmupIterations,
  retainRawSamples: true,
  native: nativeAmqp,
  framework: (fixture) => ({ plugin: amqpPlugin(amqpSettings(fixture)), key: AMQP_CAPABILITY }),
  verify: verifyAmqp,
  workload: amqpWorkload,
  complete: completeAmqpWorkload,
  close: (service) => service?.close(),
});
