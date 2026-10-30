// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startSessionsFixture } from './sessions-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';
import {
  observeSessionsParent,
  sessionsIterations,
  sessionsWarmupIterations,
} from './sessions-workload.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory',
);
const authority = await startSessionsFixture();
let stopParent = args[0] === '--smoke' ? observeSessionsParent() : undefined;
try {
  const report = await runPureComparison(
    {
      scenarioId: 'sessions-native-durable-validation-and-activity',
      fixture: authority.fixture,
      privacyValues: authority.privacyValues,
      privacyField: 'inputOccurrences',
      worker: new URL('./sessions-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend:
          'Node crypto/HMAC with the same signed authentication-event authority and PostgreSQL store',
        verifiedSuccessfulValidationsPerProfile: 2,
        invalidSecretAttemptsPerProfile: 1,
        measuredSamplesPerProfile: args[0] === '--smoke' ? sessionsIterations : 0,
        warmupValidationsPerProfile: args[0] === '--smoke' ? sessionsWarmupIterations : 0,
        samplingSupported: true,
      },
      observationCoverage:
        'Four isolated profiles validate actual public-issued MFA sessions with the same external HMAC, signed account authority and PostgreSQL CAS activity refresh. Wrong secrets fail; authentication/MFA times and original assurance remain unchanged. Parent independently verifies refreshed rows, fixed absolute expiry and actual persisted HMACs. Actual SDK exports exclude credentials and identities.',
      limitations:
        'Benchmark-only valid-session reference uses the specified record/MAC protocol, native primitives and existing shared providers. It omits complete hostile-record validation, invalid-token admission semantics, freshness policy, cancellation, retry jitter/classification and lifecycle policy. Parent-issued test-only authentication events do not establish production providers, session creation/renewal/revocation or complete cross-pod acceptance. Raw validation samples include bridge round trips and provider work. Parent campaign resources are recorded separately in durable-observation.json, without per-profile attribution; PostgreSQL server resources remain unknown. No complete resource parity, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  const successfulValidations = report.records.reduce((sum, row) => {
    assert.equal(row.completion.rejectedWrongSecrets, 1);
    assert.equal(
      row.completion.successfulValidations,
      row.verification.actualValidationsVerified +
        row.completion.sampledValidations +
        row.completion.warmupValidations,
    );
    return sum + row.completion.successfulValidations;
  }, 0);
  const durable = await authority.verify(4, successfulValidations);
  if (stopParent) {
    durable.parentCampaignResource = stopParent();
    stopParent = undefined;
  }
  const encoded = JSON.stringify(durable, null, 2) + '\n';
  for (const value of authority.privacyValues) assert.equal(encoded.includes(value), false);
  await writeFile(resolve(args[1], 'durable-observation.json'), encoded, {
    mode: 0o600,
    flag: 'wx',
  });
} finally {
  stopParent?.();
  await authority.close();
}
