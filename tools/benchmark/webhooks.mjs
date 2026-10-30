// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startWebhookFixture } from './webhooks-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory; full webhook campaigns remain separate',
);
const measured = args[0] === '--smoke';
if (measured)
  assert.equal(
    process.env.ARKENIVA_WEBHOOKS_BENCHMARK_DISPOSABLE,
    '1',
    'Webhook smoke measurements require an explicitly disposable runner',
  );
const authority = await startWebhookFixture();
try {
  const report = await runPureComparison(
    {
      scenarioId: 'webhooks-durable-native-verification',
      fixture: authority.fixture,
      privacyValues: [...Object.values(authority.fixture), ...authority.privacyValues],
      privacyField: 'inputOccurrences',
      worker: new URL('./webhooks-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: 'Node HMAC-SHA256 with actual PostgreSQL claimOnce',
        profiles: 4,
        verificationSuccessfulClaimsPerProfile: 1,
        verificationClaimAttemptsPerProfile: 2,
        scenarios: ['sign-and-durable-verify'],
        measuredSamplesPerScenario: measured ? 100 : null,
        warmupCallbacksPerScenario: measured ? 20 : null,
        traceSamplingRatio: { BASELINE: 0, FRAMEWORK: 0, STANDARD: 1, DETAILED: 1 },
        concurrency: 1,
        samplingSupported: true,
      },
      observationCoverage:
        'Native/public signature interoperability over unchanged bytes, altered serialization rejection and actual SQL one-use nonce claims in four isolated profiles; real SDK export privacy. Explicit smoke measures sequential paired signing and fresh durable verification, retaining actual Tinybench raw latency samples; actual callbacks and provider counters are independently checked against SQL readback. STANDARD and DETAILED both use diagnostic trace sampling1.',
      limitations:
        'Synthetic test principals and ephemeral external test key through an authenticated owned loopback provider bridge; this provider latency is not a production secret-store recommendation. Native baseline omits full hostile-input, rotation, timestamp and lifecycle policy; timings cannot establish policy-equivalent overhead. Timed latency includes bridge and SQL awaits; worker CPU/RSS excludes the parent bridge and PostgreSQL server. Resource samples do not describe whole-pipeline CPU/memory. STANDARD uses diagnostic sampling1 rather than normal production sampling. No outbound delivery, retry, TLS handshake, authentication authority performance, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  const persistedClaims = await authority.durableCount();
  const expected = report.records.reduce(
    (sum, row) => {
      const value = row.completion;
      for (const key of Object.keys(sum)) sum[key] += value[key];
      return sum;
    },
    {
      actualPairedCallbacks: 0,
      successfulPairedVerifications: 0,
      finalReplayDenials: 0,
      expectedAcceptedClaims: 0,
      expectedClaimAttempts: 0,
      expectedAuthorizations: 0,
      expectedSecretReads: 0,
    },
  );
  assert.equal(persistedClaims, expected.expectedAcceptedClaims);
  assert.equal(authority.state.acceptedClaims, expected.expectedAcceptedClaims);
  assert.equal(authority.state.claims, expected.expectedClaimAttempts);
  assert.equal(authority.state.authorizations, expected.expectedAuthorizations);
  assert.equal(authority.state.secretReads, expected.expectedSecretReads);
  await writeFile(
    resolve(args[1], 'durable-observation.json'),
    JSON.stringify(
      {
        persistedClaims,
        claimAttempts: authority.state.claims,
        releaseGate: false,
        ...(measured
          ? {
              measured: true,
              componentScope: 'paired-sign-and-durable-verify',
              actualPairedCallbacks: expected.actualPairedCallbacks,
              successfulPairedVerifications: expected.successfulPairedVerifications,
              finalReplayDenials: expected.finalReplayDenials,
              authorizations: authority.state.authorizations,
              secretReads: authority.state.secretReads,
            }
          : {}),
      },
      null,
      2,
    ) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await authority.close();
}
