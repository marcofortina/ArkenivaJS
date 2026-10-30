// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startOAuthFixture } from './oauth-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; durable OAuth performance sampling remains separate',
);
const authority = await startOAuthFixture();
try {
  await runPureComparison(
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
        samplingSupported: false,
      },
      observationCoverage:
        'Actual verified-HTTPS discovery and authenticated client-credentials grants in four isolated profiles; issuer request counts and persisted SQL budget independently checked. Actual standard/detailed SDK exports exclude tokens and provider data.',
      limitations:
        'Synthetic test machine principal and ephemeral external test keys through an authenticated loopback bridge. Native baseline shares the technical-budget and authority work but omits full framework admission, hostile-input, discovery endpoint and lifecycle policy. No interactive OIDC, PKCE, refresh, revocation, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  const persistedGrants = await authority.durableCount();
  assert.equal(persistedGrants, 8);
  assert.equal(authority.issuerCounts.token, 8);
  assert.equal(authority.state.authorizations, 8);
  await writeFile(
    resolve(args[1], 'durable-observation.json'),
    JSON.stringify(
      {
        persistedGrants,
        actualTokenRequests: authority.issuerCounts.token,
        authorizedGrants: authority.state.authorizations,
        releaseGate: false,
      },
      null,
      2,
    ) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await authority.close();
}
