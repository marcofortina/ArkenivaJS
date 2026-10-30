// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startGraphqlFixture } from './graphql-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory; full GraphQL campaigns remain separate',
);
const measured = args[0] === '--smoke';
if (measured)
  assert.equal(
    process.env.ARKENIVA_GRAPHQL_BENCHMARK_DISPOSABLE,
    '1',
    'GraphQL smoke measurements require an explicitly disposable runner',
  );
const authority = await startGraphqlFixture();
try {
  await runPureComparison(
    {
      scenarioId: 'graphql-native-https-authenticated-query-and-mutation-verification',
      fixture: authority.fixture,
      privacyValues: [
        ...Object.values(authority.fixture),
        'same-owned-action',
        '127.0.0.1',
        'localhost',
      ],
      privacyField: 'inputOccurrences',
      worker: new URL('./graphql-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: 'fastify@5.12.7 mercurius@16.12.1 graphql@16.14.2 jose@6.2.13',
        operationsPerProfile: measured ? null : 12,
        verificationRequestsPerProfile: 12,
        concurrency: 1,
        samplingSupported: true,
        measuredSamplesPerScenario: measured ? 100 : null,
        warmupCallbacksPerScenario: measured ? 20 : null,
        scenarios: ['simple-query', 'own-row-query', 'idempotent-mutation-retry'],
        traceSamplingRatio: { BASELINE: 0, FRAMEWORK: 0, STANDARD: 1, DETAILED: 1 },
      },
      observationCoverage:
        'Four actual certificate-verified HTTPS profiles use signed JWTs, tenant-bound rows, alias/fragment/variable selection, private getter denial, scoped mutations, bounded per-tenant idempotency and malformed document rejection. Explicit smoke measures three sequential scenarios with raw Tinybench latency samples. Actual server receipts, resolver callbacks and JSONL parent/child counts account for verification, warmup and measurement; no duplicate bytes or private input export. The diagnostic helper intentionally uses sampling1 in both STANDARD and DETAILED.',
      limitations:
        'Small valid memory corpus and test issuer. Native reference retains explicit JWT/scope/field/row checks but omits runtime provenance and complete framework complexity, admission, lifecycle and result guards; timings cannot establish policy-equivalent overhead. The named mutation reuses an existing bounded receipt and measures idempotent retries, not fresh writes or shared durability. STANDARD uses diagnostic sampling1 rather than normal production sampling. No shared business persistence, SQL-loader or subscription comparison, open-loop/sustained concurrency, complete resource accounting, confidence interval, budget, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  const observed = authority.observations();
  assert.equal(observed.jwks, 4);
  assert.equal(observed.unknown, 0);
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify(
      {
        actualJwksRequests: observed.jwks,
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
