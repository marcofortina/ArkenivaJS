// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import assert from 'node:assert/strict';
import { createIssuer } from './http-issuer.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const issuer = await createIssuer();
try {
  const claims = { tenant_id: 'owned-auth-private-tenant', scope: 'owned:comparison' };
  const token = await issuer.token({ claims });
  const parts = token.split('.');
  parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
  const fixture = {
    issuer: issuer.origin,
    audience: issuer.audience,
    token,
    tenant: claims.tenant_id,
    scope: claims.scope,
    invalidTokens: [
      parts.join('.'),
      await issuer.token({ issuer: 'https://foreign.invalid', claims }),
      await issuer.token({ audience: 'api://foreign', claims }),
      await issuer.token({ expiration: '-1h', claims }),
    ],
  };
  await runPureComparison({
    scenarioId: 'auth-native-jose-verification-comparison',
    fixture,
    privacyValues: [
      fixture.issuer,
      fixture.audience,
      fixture.token,
      fixture.tenant,
      fixture.scope,
      ...fixture.invalidTokens,
      'synthetic-user',
      '127.0.0.1',
    ],
    privacyField: 'inputOccurrences',
    worker: new URL('./auth-worker.mjs', import.meta.url),
    inputs: {
      nativeBackend: 'jose@6.2.13',
      algorithm: 'RS256',
      samplesPerOperation: 1000,
      warmupIterations: 100,
      concurrency: 1,
    },
    observationCoverage:
      'Actual native JOSE and public security-plugin verification through an owned JWKS issuer in four isolated profiles. Verifies signed identity, scope/tenant resolution and invalid signature/issuer/audience/expiry rejection. Successful/rejected verification counters match actual completed calls; reports exclude tokens and claims.',
    limitations:
      'Synthetic test-only HTTP loopback issuer and valid fixed claim projection. Native baseline omits full hostile-claim normalization, provenance brands, tenant authority, bounded transport, cancellation and lifecycle policy. Actual installed SDK emits no synthetic per-verification instruments; exporter delivery is separate. No production insecure transport, session/MFA assurance, key rotation, provider CPU, dedicated-runner budget, five repetitions or one-hour soak acceptance.',
  });
  const observation = issuer.observations();
  assert.equal(observation.jwks, 4);
  assert.equal(observation.unknown, 0);
  await writeFile(
    resolve(process.argv[3], 'protocol-observation.json'),
    JSON.stringify({ actualJwksRequests: observation.jwks, releaseGate: false }, null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  await issuer.close();
}
