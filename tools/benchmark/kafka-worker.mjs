// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { kafkaPlugin, KAFKA_CAPABILITY } from '@arkenivajs/messaging-kafka';
import { runPureWorker } from './pure-worker.mjs';
import { kafkaSettings, nativeKafka, verifyKafka } from './kafka-workload.mjs';

runPureWorker({
  name: 'kafka',
  native: nativeKafka,
  framework(fixture, mode) {
    fixture.marker =
      fixture.markers[['BASELINE', 'FRAMEWORK', 'STANDARD', 'DETAILED'].indexOf(mode)];
    return { plugin: kafkaPlugin(kafkaSettings(fixture)), key: KAFKA_CAPABILITY };
  },
  verify: verifyKafka,
  close: (service) => service?.close(),
});
