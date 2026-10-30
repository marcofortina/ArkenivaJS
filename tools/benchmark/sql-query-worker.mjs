// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import { runPureWorker } from './pure-worker.mjs';
import {
  sqlQueryConnection,
  nativeSqlQuery,
  verifySqlQuery,
  sqlQueryWorkload,
  completeSqlQuery,
} from './sql-query-workload.mjs';

runPureWorker({
  name: 'sql-query',
  retainRawSamples: true,
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  native: nativeSqlQuery,
  framework(fixture) {
    sqlQueryConnection(fixture);
    process.env.ARKENIVA_SQL_QUERY_COMPARISON_URL = fixture.url;
    return {
      plugin: postgresPlugin(),
      key: COMPONENTS.sql,
      databases: {
        main: {
          driver: 'postgresql',
          connectionStringEnv: 'ARKENIVA_SQL_QUERY_COMPARISON_URL',
          poolMax: 2,
        },
      },
    };
  },
  verify: verifySqlQuery,
  workload: sqlQueryWorkload,
  complete: completeSqlQuery,
  close: (service) => service.close(),
});
