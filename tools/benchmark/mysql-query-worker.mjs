// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { mysqlPlugin } from '@arkenivajs/database-mysql';
import { runPureWorker } from './pure-worker.mjs';
import {
  mysqlQueryConnection,
  nativeMysqlQuery,
  verifyMysqlQuery,
  mysqlQueryWorkload,
  completeMysqlQuery,
} from './mysql-query-workload.mjs';

runPureWorker({
  name: 'mysql-query',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  native: nativeMysqlQuery,
  framework(fixture) {
    mysqlQueryConnection(fixture);
    process.env.ARKENIVA_MYSQL_COMPARISON_URL = fixture.url;
    return {
      plugin: mysqlPlugin(),
      key: COMPONENTS.sql,
      databases: {
        main: { driver: 'mysql', connectionStringEnv: 'ARKENIVA_MYSQL_COMPARISON_URL', poolMax: 2 },
      },
    };
  },
  verify: verifyMysqlQuery,
  workload: mysqlQueryWorkload,
  complete: completeMysqlQuery,
  close: (service) => service?.close(),
});
