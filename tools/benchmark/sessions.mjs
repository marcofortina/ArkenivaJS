// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startSessionsFixture } from './sessions-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; complete session provider resource sampling remains separate',
);
const authority = await startSessionsFixture();
try {
  await runPureComparison(
    {
      scenarioId: 'sessions-native-durable-validation-and-activity',
      fixture: authority.fixture,
      privacyValues: authority.privacyValues,
      privacyField: 'inputOccurrences',
      worker: new URL('./sessions-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend:
          'Node crypto/HMAC with the same signed authentication-event authority and PostgreSQL store',
        successfulValidationsPerProfile: 2,
        invalidSecretAttemptsPerProfile: 1,
        samplingSupported: false,
      },
      observationCoverage:
        'Four isolated profiles validate actual public-issued MFA sessions with the same external HMAC, signed account authority and PostgreSQL CAS activity refresh. Wrong secrets fail; authentication/MFA times and original assurance remain unchanged. Parent independently verifies refreshed rows, fixed absolute expiry and actual persisted HMACs. Actual SDK exports exclude credentials and identities.',
      limitations:
        'Benchmark-only valid-session reference uses the specified record/MAC protocol, native primitives and existing shared providers. It omits complete hostile-record validation, invalid-token admission semantics, freshness policy, cancellation, retry jitter/classification and lifecycle policy. Parent-issued test-only authentication events do not establish production providers, session creation/renewal/revocation or complete cross-pod acceptance. No complete provider/server resource sampling, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  await writeFile(
    resolve(args[1], 'durable-observation.json'),
    JSON.stringify(await authority.verify(4), null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await authority.close();
}
