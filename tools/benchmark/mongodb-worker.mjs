// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { mongodbPlugin } from '@arkenivajs/database-mongodb';
import { runPureWorker } from './pure-worker.mjs';
import {
  nativeMongo,
  mongodbConnection,
  verifyMongo,
  prepareMongoRead,
  mongoReadWorkload,
  completeMongoRead,
} from './mongodb-workload.mjs';

runPureWorker({
  name: 'mongodb',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  native: nativeMongo,
  framework(fixture) {
    mongodbConnection(fixture);
    process.env.ARKENIVA_MONGODB_COMPARISON_URL = fixture.url;
    return {
      plugin: mongodbPlugin(),
      key: COMPONENTS.mongo,
      databases: {
        documents: { driver: 'mongodb', connectionStringEnv: 'ARKENIVA_MONGODB_COMPARISON_URL' },
      },
    };
  },
  async verify(service, fixture) {
    const result = await verifyMongo(service, fixture);
    if (fixture.readCollection !== undefined) await prepareMongoRead(service, fixture);
    return result;
  },
  workload: mongoReadWorkload,
  complete: completeMongoRead,
  close: (service) => service?.close(),
});
