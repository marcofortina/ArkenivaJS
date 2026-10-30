// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { startRoutingFixture, routingPrivateValues } from './routing-fixture.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; routing sampling requires separate scale and policy-equivalence work',
);
const authority = await startRoutingFixture();
try {
  await runPureComparison(
    {
      scenarioId: 'tenant-routing-native-https-local-catalog-verification',
      fixture: authority.fixture,
      privacyValues: routingPrivateValues(authority.fixture),
      privacyField: 'privateInputOccurrences',
      worker: new URL('./routing-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: 'fastify@5.12.7 jose@6.2.13 canonicalize@5.1.0',
        operationsPerProfile: 19,
        registryOperations: 3,
        registryBindings: 6,
        localImplementations: 4,
        boundTenants: 2,
        capabilityLimit: 1,
        activationGeneration: 7,
        samplingSupported: false,
      },
      observationCoverage:
        'Four actual certificate-verified HTTPS profiles check signed JWTs, schema validation, tenant-derived local dispatch, forbidden-operation effects, known foreign-row absence, immutable logical-operation mapping, revision/generation and private capability discovery including explicit overflow rejection. Standard/detailed additionally verify actual JSONL child/HTTP parentage, no duplicated child bytes and native SDK private-input exclusion. Trusted tenant/registry identifiers remain allowed trace diagnostics.',
      limitations:
        'Functional fixed-memory catalog and synthetic issuer only. Native reference retains signature/scope/binding/row authorization but omits framework provenance brands, complete hostile-input/registry validation, operation admission/deadline/cancellation and lifecycle policy. No policy-equivalent overhead, REST-without-router profile, HTTP upstream, 100/10000 bindings, large discovery, cold start, rollout, latency/CPU/RSS/throughput, variance budget, five repetitions or one-hour soak acceptance.',
    },
    args,
  );
  const observed = authority.observations();
  assert.equal(observed.jwks, 4);
  assert.equal(observed.unknown, 0);
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify({ actualJwksRequests: observed.jwks, releaseGate: false }, null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await authority.close();
}
