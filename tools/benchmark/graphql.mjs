// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startGraphqlFixture } from './graphql-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; full GraphQL measurements remain separate',
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
        operationsPerProfile: 12,
        concurrency: 1,
        samplingSupported: false,
      },
      observationCoverage:
        'Four actual certificate-verified HTTPS profiles use signed JWTs, tenant-bound rows, alias/fragment/variable selection, private getter denial, scoped mutations, per-tenant idempotency and malformed document rejection. Standard/detailed additionally verify actual JSONL technical usage parentage without duplicate bytes and native SDK privacy.',
      limitations:
        'Small valid memory corpus and test issuer. Native reference retains explicit JWT/scope/field/row checks but omits runtime provenance and complete framework complexity, admission, lifecycle and result guards. No shared business persistence, SQL-loader or subscription comparison, complete resource accounting, sustained concurrency, budget, five repetitions or one-hour soak acceptance.',
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
