// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { startSamlFixture } from './saml-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';
import { samlPrivacyValues } from './saml-workload.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory',
);
assert.ok(
  args[0] !== '--smoke' || process.env.ARKENIVA_SAML_BENCHMARK_DISPOSABLE === '1',
  'SAML smoke requires an explicitly disposable measurement environment',
);
const authority = await startSamlFixture();
try {
  const fixture = {
    ...authority.fixture,
    sampleRedirect: args[0] === '--smoke',
    sampleReturnPath: '/owned-saml-correlation-' + randomBytes(16).toString('hex'),
  };
  await runPureComparison(
    {
      scenarioId: 'saml-native-signed-redirect-request-and-post-response-verification',
      fixture,
      privacyValues: samlPrivacyValues(fixture),
      privacyField: 'inputOccurrences',
      worker: new URL('./saml-worker.mjs', import.meta.url),
      superviseProcessTree: true,
      inputs: {
        nativeBackend: '@node-saml/node-saml@5.1.0',
        requestsPerProfile: args[0] === '--smoke' ? 123 : 3,
        actualIdpRequestsPerProfile: 3,
        binding: 'HTTP-Redirect requests and HTTP-POST responses',
        samplingSupported: true,
        sampledRedirectCreationsPerProfile: args[0] === '--smoke' ? 100 : 0,
        warmupRedirectCreationsPerProfile: args[0] === '--smoke' ? 20 : 0,
      },
      observationCoverage:
        'Actual signed SP requests reach a separately owned verified HTTPS IdP bridge, which checks every SP signature and request/ACS/issuer correlation before signing a response. Four profiles retain signed metadata, actual signed identity, replay, tampering and audience rejection without trusting tenant attributes. Parent independently counts twelve signature-verified requests/responses. Optional smoke creates signed Redirect transfers and independently verifies exact RSA-SHA256 query bytes, bounded XML, pinned destination/ACS/issuer and unique correlation for every callback. Actual SDK exports omit assertions, identities, private return-path correlation and keys.',
      limitations:
        'Fixed generic federation profile and ephemeral unit-only replay/correlation stores; no durable multi-pod replay claim. Measured creation includes independent signature/XML checks but sends no measured IdP request and is not an ACS verification or browser transaction. Native reference omits complete XML admission, durable persistence, worker cancellation isolation, logout and framework identity provenance; no equivalent-policy overhead claim. Whole-lifecycle supervision includes Node worker-thread CPU/RSS through their owning process; parent collector, PKI generation and HTTPS IdP resources are excluded. Sampled summed RSS is not exact peak/PSS and can repeat shared pages or miss short peaks. Diagnostic STANDARD/DETAILED samplingRatio1, no production sampling budget, accreditation, dedicated-runner gate, five repetitions, one-hour soak or release acceptance.',
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
