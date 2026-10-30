// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { runPureComparison } from './pure-comparison.mjs';
import { redisConnection, nativeRedis, redisKeys } from './redis-workload.mjs';

assert.equal(
  process.env.ARKENIVA_REDIS_DISPOSABLE,
  '1',
  'Use only an explicitly owned disposable Redis fixture',
);
assert.ok(process.env.ARKENIVA_REDIS_URL, 'The private Redis fixture environment is required');
const fixture = {
  url: process.env.ARKENIVA_REDIS_URL,
  namespace: 'redis-comparison:' + randomBytes(16).toString('hex') + ':',
  marker: 'owned-redis-private-value',
};
const { url } = redisConnection(fixture);
await runPureComparison({
  scenarioId: 'redis-native-portable-operation-comparison',
  fixture,
  privacyValues: [
    ...Object.values(fixture),
    decodeURIComponent(url.username),
    decodeURIComponent(url.password),
    url.searchParams.get('sslca'),
    'localhost',
    '127.0.0.1',
  ],
  privacyField: 'inputOccurrences',
  worker: new URL('./redis-worker.mjs', import.meta.url),
  inputs: {
    operations: ['get', 'set', 'increment', 'del', 'publish'],
    nativeBackend: 'redis@6.3.0 with verified TLS',
    commandsPerRoundtrip: 4,
    samplesPerOperation: 100,
    warmupIterations: 20,
    concurrency: 1,
  },
  observationCoverage:
    'Actual UTF8/BOM data, NX outcomes, native TTL/expiry, counter state, deletion counts and observed subscriber message in four isolated profiles; real SDK exports exclude values, keys and credentials.',
  limitations:
    'Small valid corpus and safe counter operands only. Native baseline omits wrapper Lua byte/UTF8/integer guards, admission, cancellation and lifecycle policy. Roundtrip timing covers acknowledged set,get,increment,delete together; control reads and subscriber setup are outside sampling. Whole child resources exclude Redis server CPU. PubSub is ephemeral, with no durable processing acknowledgement. No dedicated-runner budget, five repetitions or one-hour soak acceptance.',
});
const inspection = await nativeRedis(fixture);
try {
  for (const key of redisKeys)
    assert.equal(
      await inspection.inspect().get(inspection.physical(fixture.namespace + key)),
      null,
    );
} finally {
  await inspection.close();
}
await writeFile(
  resolve(process.argv[3], 'protocol-observation.json'),
  JSON.stringify({ ownedKeysRemaining: 0, releaseGate: false }, null, 2) + '\n',
  { mode: 0o600, flag: 'wx' },
);
