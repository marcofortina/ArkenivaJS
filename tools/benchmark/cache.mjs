// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { runPureComparison } from './pure-comparison.mjs';
import { cacheConnection } from './cache-workload.mjs';

assert.equal(
  process.env.ARKENIVA_REDIS_DISPOSABLE,
  '1',
  'Use only an explicitly owned disposable Redis fixture',
);
assert.ok(process.env.ARKENIVA_REDIS_URL, 'The private Redis fixture environment is required');
const fixture = {
  url: process.env.ARKENIVA_REDIS_URL,
  namespace: 'cache-comparison:' + randomBytes(16).toString('hex') + ':',
  marker: 'owned-cache-private-value',
};
const { url } = cacheConnection(fixture);
await runPureComparison({
  scenarioId: 'cache-native-redis-comparison',
  fixture,
  privacyValues: [
    ...Object.values(fixture),
    decodeURIComponent(url.password),
    decodeURIComponent(url.username),
    url.searchParams.get('sslca'),
    '127.0.0.1',
    'localhost',
  ],
  privacyField: 'inputOccurrences',
  worker: new URL('./cache-worker.mjs', import.meta.url),
  inputs: {
    operations: ['roundtrip'],
    nativeBackend: 'redis@6.3.0 with Ajv envelope validation',
    commandsPerRoundtrip: 3,
    samplesPerOperation: 100,
    warmupIterations: 20,
    concurrency: 1,
  },
  observationCoverage:
    'Real verified-TLS Redis storage, exact versioned JSON, finite TTL, actual expiry and deletion results, corrupt-state rejection and export privacy in four isolated profiles.',
  limitations:
    'Synthetic valid JSON corpus; native baseline validates the envelope but omits framework recursive traversal bounds, capture, admission and lifecycle policy. Direct raw reads inspect actual stored state outside sampling. Roundtrip latency covers acknowledged set,get,delete together. No verified tenant scope, multi-pod workload, backend CPU, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
});
