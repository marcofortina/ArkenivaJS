// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { mongodbPlugin } from '@arkenivajs/database-mongodb';
import { runPureWorker } from './pure-worker.mjs';
import { nativeMongo, mongodbConnection, verifyMongo } from './mongodb-workload.mjs';

runPureWorker({
  name: 'mongodb',
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
  verify: verifyMongo,
  close: (service) => service?.close(),
});
