// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { runPureComparison } from './pure-comparison.mjs';
import { startPasswordFixture } from './password-fixture.mjs';
import { passwordPolicy } from './password-workload.mjs';
assert.equal(
  process.argv[2],
  '--verify',
  'Only --verify is supported for the bounded durable KDF comparison',
);
const authority = await startPasswordFixture();
try {
  await runPureComparison({
    scenarioId: 'password-native-functional-comparison',
    fixture: authority.fixture,
    privacyValues: [...Object.values(authority.fixture), '$argon2id$'],
    privacyField: 'inputOccurrences',
    worker: new URL('./password-worker.mjs', import.meta.url),
    inputs: {
      operations: ['hash', 'verify', 'needsRehash'],
      nativeBackend: 'argon2@0.45.1',
      memoryCostKiB: passwordPolicy.memoryCostKiB,
      timeCost: passwordPolicy.timeCost,
      parallelism: passwordPolicy.parallelism,
      concurrency: 1,
      samplingSupported: false,
      actualDurableBudget: true,
    },
    observationCoverage:
      'Actual native Argon2id hash/verification and public service with real SQL budget updates in four isolated profiles. Actual standard/detailed exports checked without plaintext, PHCs, credentials or provider endpoints.',
    limitations:
      'Bounded valid KDF corpus only, not policy calibration. Public service includes durable budget calls via an owned loopback bridge; bare Argon2 does not. Reset/authority/committer ports deny all operations. No production KDF recommendation, equivalent end-to-end cost, memory budget, queue-saturation measurement, repeated campaign or soak acceptance.',
  });
  const persistedBudget = await authority.durableCount();
  assert.equal(persistedBudget, 15);
  assert.equal(authority.state.completedCalls, 30);
  await writeFile(
    resolve(process.argv[3], 'durable-observation.json'),
    JSON.stringify(
      { persistedBudget, completedStoreCalls: authority.state.completedCalls, releaseGate: false },
      null,
      2,
    ) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await authority.close();
}
