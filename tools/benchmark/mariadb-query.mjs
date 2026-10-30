// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';
import { mariadbQueryConnection } from './mariadb-query-workload.mjs';

assert.equal(
  process.env.ARKENIVA_MARIADB_DISPOSABLE,
  '1',
  'Use only the explicitly owned disposable MariaDB fixture',
);
const fixture = {
  url: process.env.ARKENIVA_MARIADB_URL,
  marker: "owned-mariadb-private-value-π ' ; --",
  exact: '9007199254740993',
};
const url = mariadbQueryConnection(fixture);
await runPureComparison({
  scenarioId: 'mariadb-native-prepared-query-comparison',
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
  worker: new URL('./mariadb-query-worker.mjs', import.meta.url),
  inputs: {
    nativeBackend: 'mariadb@3.5.4',
    operation: 'queryOne',
    poolMax: 2,
    samplesPerOperation: 100,
    warmupIterations: 20,
    concurrency: 1,
  },
  observationCoverage:
    'Actual verified-TLS MariaDB prepared rows, repeated named binds and exact native bigint values in four isolated profiles. Public native pool counters verify idle/drained checkouts and zero queued tasks. Actual SDK exports exclude connection data and bindings.',
  limitations:
    'Fixed read-only SELECT corpus. Native baseline matches reset, UTF8/UTC/sql_mode policy, prepared result streaming and statement close but omits framework capture, bind compilation, fingerprinting, admission, cancellation and lifecycle policy. MariaDB bigint semantics are preserved independently of MySQL text results. No transaction, write outcome, server CPU, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
});
