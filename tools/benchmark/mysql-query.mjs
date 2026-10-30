// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';
import { mysqlQueryConnection } from './mysql-query-workload.mjs';

assert.equal(
  process.env.ARKENIVA_MYSQL_DISPOSABLE,
  '1',
  'Use only the explicitly owned disposable MySQL fixture',
);
const fixture = {
  url: process.env.ARKENIVA_MYSQL_URL,
  marker: "owned-mysql-private-value-π ' ; --",
  exact: '9007199254740993',
};
const url = mysqlQueryConnection(fixture);
await runPureComparison({
  scenarioId: 'mysql-native-prepared-query-comparison',
  fixture,
  privacyValues: [
    ...Object.values(fixture),
    decodeURIComponent(url.username),
    decodeURIComponent(url.password),
    url.searchParams.get('sslca'),
    '127.0.0.1',
    'localhost',
  ],
  privacyField: 'inputOccurrences',
  worker: new URL('./mysql-query-worker.mjs', import.meta.url),
  inputs: {
    nativeBackend: 'mysql2@3.24.6',
    operation: 'queryOne',
    poolMax: 2,
    samplesPerOperation: 100,
    warmupIterations: 20,
    concurrency: 1,
  },
  observationCoverage:
    'Actual verified-TLS MySQL prepared rows, repeated named binds and native bigint text precision in four isolated profiles. Tracked checkouts, pending acquisitions and observer/cleanup failures are checked. Actual SDK exports exclude connection data and bindings.',
  limitations:
    'Fixed read-only SELECT corpus. The native baseline matches explicit reset, UTF8/UTC/sql_mode policy and prepared result streaming but omits framework capture, bind compilation, fingerprinting, admission, cancellation and lifecycle policy. The native driver has no stable public pool total/idle/queue counters; none are invented. No transaction, write outcome, all-driver normalization, server CPU, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
});
