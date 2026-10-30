// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startOAuthFixture } from './oauth-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';
import { oauthIterations, oauthWarmupIterations } from './oauth-workload.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory',
);
const authority = await startOAuthFixture();
try {
  const report = await runPureComparison(
    {
      scenarioId: 'oauth-native-durable-machine-grant-verification',
      fixture: authority.fixture,
      trustAnchorFile: authority.trustAnchorFile,
      privacyValues: [...Object.values(authority.fixture), ...authority.privacyValues, 'access.'],
      privacyField: 'inputOccurrences',
      worker: new URL('./oauth-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: 'openid-client@6.8.8 with actual PostgreSQL technical budget',
        grantsPerProfile: 2,
        concurrency: 1,
        samplingSupported: true,
        measuredSamplesPerProfile: args[0] === '--smoke' ? oauthIterations : 0,
        warmupGrantsPerProfile: args[0] === '--smoke' ? oauthWarmupIterations : 0,
      },
      observationCoverage:
        'Actual verified-HTTPS discovery and authenticated client-credentials grants in four isolated profiles; every measured callback awaits its actual token response and durable SQL budget mutation. Every returned grant is checked privately after timing. Parent independently checks issuer request counts and persisted SQL budget, without opaque-token introspection. Actual standard/detailed SDK exports exclude tokens and provider data.',
      limitations:
        'Synthetic test machine principal and ephemeral external test keys through an authenticated loopback bridge. Native baseline shares the technical-budget and authority work but omits full framework admission, hostile-input, discovery endpoint and lifecycle policy. PKCE, interactive state and nonce do not apply to client_credentials and are not measured. Child process CPU includes its crypto threadpool; parent HTTPS issuer/provider/SQL-client and PostgreSQL server resources are excluded and separately unknown. No interactive OIDC, refresh, revocation, end-to-end equivalence, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  const expectedGrants = report.records.reduce((sum, row) => {
      assert.equal(
        row.completion.checkedGrants,
        row.completion.sampledGrants + row.completion.warmupGrants,
      );
      return sum + row.verification.authenticatedMachineGrants + row.completion.checkedGrants;
    }, 0),
    observation = await authority.verify(expectedGrants),
    encoded = JSON.stringify(observation, null, 2) + '\n';
  for (const value of [...Object.values(authority.fixture), ...authority.privacyValues, 'access.'])
    assert.equal(encoded.includes(value), false);
  await writeFile(resolve(args[1], 'durable-observation.json'), encoded, {
    mode: 0o600,
    flag: 'wx',
  });
} finally {
  await authority.close();
}
