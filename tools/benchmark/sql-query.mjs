// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';
import { sqlQueryConnection } from './sql-query-workload.mjs';

assert.equal(
  process.env.ARKENIVA_POSTGRES_DISPOSABLE,
  '1',
  'Use only an explicitly owned disposable PostgreSQL fixture',
);
assert.ok(
  process.env.ARKENIVA_POSTGRES_URL,
  'The private PostgreSQL fixture environment is required',
);
const fixture = {
  url: process.env.ARKENIVA_POSTGRES_URL,
  marker: "owned-sql-private-value ' ; --",
  exact: '9007199254740993',
};
const { url } = sqlQueryConnection(fixture);
await runPureComparison({
  scenarioId: 'sql-native-postgres-query-comparison',
  fixture,
  privacyValues: [
    ...Object.values(fixture),
    decodeURIComponent(url.username),
    decodeURIComponent(url.password),
    url.searchParams.get('sslrootcert'),
    '127.0.0.1',
    'localhost',
  ],
  privacyField: 'inputOccurrences',
  worker: new URL('./sql-query-worker.mjs', import.meta.url),
  inputs: {
    nativeBackend: 'pg@8.23.1 and pg-cursor@2.22.1',
    operation: 'queryOne',
    poolMax: 2,
    samplesPerOperation: 100,
    warmupIterations: 20,
    concurrency: 1,
  },
  observationCoverage:
    'Actual verified-TLS PostgreSQL named/positional bound rows, repeated parameters and bigint text precision in four isolated profiles. Native pool readback confirms no queued or retained checkout; real SDK exports exclude bindings and connection data.',
  limitations:
    'Fixed read-only SELECT corpus. Native baseline matches explicit session reset/UTF8 policy and bounded two-row cursor cleanup but omits framework capture, bind compilation, fingerprinting, admission, cancellation and lifecycle policy. No SQL parser is replaced by text substitution. No transaction, write outcome, server CPU, all-driver, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
});
