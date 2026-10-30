// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { runPureComparison } from './pure-comparison.mjs';
import { startPasswordFixture } from './password-fixture.mjs';
import {
  passwordPolicy,
  passwordIterations,
  passwordWarmupIterations,
} from './password-workload.mjs';
const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory',
);
const authority = await startPasswordFixture(args[0] === '--smoke');
try {
  const report = await runPureComparison(
    {
      scenarioId: 'password-native-functional-comparison',
      fixture: authority.fixture,
      privacyValues: [
        ...Object.values(authority.fixture).filter((value) => typeof value === 'string'),
        '$argon2id$',
      ],
      privacyField: 'inputOccurrences',
      worker: new URL('./password-worker.mjs', import.meta.url),
      inputs: {
        operations: ['hash', 'verify', 'needsRehash'],
        nativeBackend: 'argon2@0.45.1',
        memoryCostKiB: passwordPolicy.memoryCostKiB,
        timeCost: passwordPolicy.timeCost,
        parallelism: passwordPolicy.parallelism,
        concurrency: 1,
        samplingSupported: true,
        measuredOperation: 'Positive verification against one current untimed native PHC',
        samplesPerProfile: args[0] === '--smoke' ? passwordIterations : 0,
        warmupPerProfile: args[0] === '--smoke' ? passwordWarmupIterations : 0,
        actualDurableBudget: true,
      },
      observationCoverage:
        'Actual native Argon2id hash/verification and public service with real SQL budget updates in four isolated profiles. Optional100-sample20-warmup smoke verifies the same current PHC, created outside timing, and privately checks480 positive/no-rehash results. Parent independently requires375 successful SQL reservations and750 store calls, including15 original verification reservations. Actual standard/detailed exports checked without plaintext, PHCs, credentials or provider endpoints.',
      limitations:
        'Bounded valid KDF corpus only, not policy calibration. Timed work verifies a fixed valid PHC and includes the public durable budget calls via an owned loopback bridge; bare Argon2 does not. No native/framework admission-policy parity or hash-generation timing claim. Reset/authority/committer ports deny all operations. Worker process CPU includes actual native KDF threads; parent provider/SQL client and PostgreSQL server resources are excluded and unknown. No production KDF recommendation, complete end-to-end resource parity, calibrated memory budget, queue-saturation measurement, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  const frameworkSamples = report.records
    .filter((row) => row.mode !== 'BASELINE')
    .reduce((sum, row) => {
      assert.equal(
        row.completion.checkedVerifications,
        row.completion.sampledVerifications + row.completion.warmupVerifications,
      );
      return sum + row.completion.checkedVerifications;
    }, 0);
  const persistedBudget = await authority.durableCount();
  assert.equal(persistedBudget, 15 + frameworkSamples);
  assert.equal(authority.state.completedCalls, 2 * persistedBudget);
  const observation =
    args[0] === '--smoke'
      ? await authority.verifySampled(persistedBudget)
      : {
          persistedBudget,
          completedStoreCalls: authority.state.completedCalls,
          releaseGate: false,
        };
  const encoded = JSON.stringify(observation, null, 2) + '\n';
  for (const value of Object.values(authority.fixture).filter((value) => typeof value === 'string'))
    assert.equal(encoded.includes(value), false);
  await writeFile(resolve(args[1], 'durable-observation.json'), encoded, {
    mode: 0o600,
    flag: 'wx',
  });
} finally {
  await authority.close();
}
