// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { mariadbPlugin } from '@arkenivajs/database-mariadb';
import { runPureWorker } from './pure-worker.mjs';
import {
  mariadbQueryConnection,
  nativeMariadbQuery,
  verifyMariadbQuery,
  mariadbQueryWorkload,
  completeMariadbQuery,
} from './mariadb-query-workload.mjs';

runPureWorker({
  name: 'mariadb-query',
  retainRawSamples: true,
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  native: nativeMariadbQuery,
  framework(fixture) {
    mariadbQueryConnection(fixture);
    process.env.ARKENIVA_MARIADB_COMPARISON_URL = fixture.url;
    return {
      plugin: mariadbPlugin(),
      key: COMPONENTS.sql,
      databases: {
        main: {
          driver: 'mariadb',
          connectionStringEnv: 'ARKENIVA_MARIADB_COMPARISON_URL',
          poolMax: 2,
        },
      },
    };
  },
  verify: verifyMariadbQuery,
  workload: mariadbQueryWorkload,
  complete: completeMariadbQuery,
  close: (service) => service?.close(),
});
