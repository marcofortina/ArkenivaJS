// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startWebhookFixture } from './webhooks-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; durable performance sampling remains separate',
);
const authority = await startWebhookFixture();
try {
  await runPureComparison(
    {
      scenarioId: 'webhooks-durable-native-verification',
      fixture: authority.fixture,
      privacyValues: [...Object.values(authority.fixture), ...authority.privacyValues],
      privacyField: 'inputOccurrences',
      worker: new URL('./webhooks-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: 'Node HMAC-SHA256 with actual PostgreSQL claimOnce',
        profiles: 4,
        successfulClaimsPerProfile: 1,
        claimAttemptsPerProfile: 2,
        concurrency: 1,
        samplingSupported: false,
      },
      observationCoverage:
        'Native/public signature interoperability over unchanged bytes, altered serialization rejection and actual SQL one-use nonce claims in four isolated profiles; real SDK export privacy.',
      limitations:
        'Synthetic test principals and ephemeral external test key through an authenticated owned loopback provider bridge; this provider latency is not a production secret-store recommendation. Native baseline omits full hostile-input, rotation, timestamp and lifecycle policy. No outbound delivery, retry, TLS handshake, authentication authority performance, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  const persistedClaims = await authority.durableCount();
  assert.equal(persistedClaims, 4);
  assert.equal(authority.state.acceptedClaims, 4);
  assert.equal(authority.state.claims, 8);
  await writeFile(
    resolve(args[1], 'durable-observation.json'),
    JSON.stringify(
      { persistedClaims, claimAttempts: authority.state.claims, releaseGate: false },
      null,
      2,
    ) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await authority.close();
}
