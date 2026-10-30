// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startSamlFixture } from './saml-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; complete SAML worker/resource and durable-store comparison remains separate',
);
const authority = await startSamlFixture();
try {
  await runPureComparison(
    {
      scenarioId: 'saml-native-signed-redirect-request-and-post-response-verification',
      fixture: authority.fixture,
      privacyValues: [
        ...Object.values(authority.fixture),
        'synthetic-account',
        'untrusted-tenant-hint',
        'private-session-index',
        '127.0.0.1',
        'localhost',
      ],
      privacyField: 'inputOccurrences',
      worker: new URL('./saml-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: '@node-saml/node-saml@5.1.0',
        requestsPerProfile: 3,
        binding: 'HTTP-Redirect requests and HTTP-POST responses',
        samplingSupported: false,
      },
      observationCoverage:
        'Actual signed SP requests reach a separately owned verified HTTPS IdP bridge, which checks every SP signature and request/ACS/issuer correlation before signing a response. Four profiles verify signed metadata, actual signed identity, replay, tampering and audience rejection without trusting tenant attributes. Parent independently counts twelve signature-verified requests/responses. Actual SDK exports omit assertions, identities and keys.',
      limitations:
        'Fixed synthetic generic federation profile, ephemeral unit-only replay/correlation stores and bearer-authenticated IdP fixture bridge; not a browser cookie/ACS transaction, actual durable multi-pod replay or federation accreditation. Native valid-profile reference omits complete XML admission, state persistence, isolated worker cancellation, logout and framework identity provenance. No complete native worker/PKI/server resource sampling or full campaign acceptance.',
    },
    args,
  );
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify(authority.verify(4), null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await authority.close();
}
