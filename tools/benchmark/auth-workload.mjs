// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createRemoteJWKSet, jwtVerify } from 'jose';

export function authConnection(fixture) {
  const url = new URL(fixture.issuer);
  assert.equal(url.protocol, 'http:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.ok(url.port && !url.username && !url.password && !url.search && !url.hash);
  assert.equal(url.pathname, '/');
  return new URL('/keys', url);
}

/** Native JOSE verifies actual tokens; the fixed projection omits application provenance/lifecycle policy. */
export function nativeAuth(fixture) {
  const keys = createRemoteJWKSet(authConnection(fixture), {
    cooldownDuration: 30000,
    cacheMaxAge: 300000,
    timeoutDuration: 5000,
  });
  const counts = { verified: 0, rejected: 0, observerFailures: 0 };
  return {
    async verifyBearer(header) {
      try {
        assert.equal(typeof header, 'string');
        assert.ok(header.startsWith('Bearer '));
        const token = header.slice(7);
        const { payload } = await jwtVerify(token, keys, {
          issuer: fixture.issuer,
          audience: fixture.audience,
          algorithms: ['RS256'],
          typ: 'JWT',
          clockTolerance: 0,
          requiredClaims: ['sub', 'iss', 'aud', 'exp'],
        });
        counts.verified++;
        return {
          issuer: payload.iss,
          subject: payload.sub,
          audience: typeof payload.aud === 'string' ? [payload.aud] : payload.aud,
          scopes: [...new Set(payload.scope.split(' ').filter(Boolean))],
          claims: payload,
        };
      } catch (cause) {
        counts.rejected++;
        throw cause;
      }
    },
    requireScope(identity, scope) {
      assert.ok(identity.scopes.includes(scope));
    },
    tenantFrom(identity) {
      assert.equal(identity.claims.tenant_id, fixture.tenant);
      return { tenantId: fixture.tenant, identity };
    },
    stats: () => ({ ...counts }),
  };
}

export async function verifyAuth(service, fixture) {
  const identity = await service.verifyBearer('Bearer ' + fixture.token);
  assert.equal(identity.issuer, fixture.issuer);
  assert.equal(identity.subject, 'synthetic-user');
  assert.deepEqual([...identity.audience], [fixture.audience]);
  assert.deepEqual([...identity.scopes], [fixture.scope]);
  service.requireScope(identity, fixture.scope);
  assert.throws(() => service.requireScope(identity, 'absent'));
  const tenant = service.tenantFrom(identity);
  assert.equal(tenant.tenantId, fixture.tenant);
  assert.equal(tenant.identity, identity);
  for (const token of fixture.invalidTokens)
    await assert.rejects(service.verifyBearer('Bearer ' + token));
  return {
    actualSignatureAndClaimsVerified: true,
    issuerAudienceAndExpiryRejected: true,
    tamperedSignatureRejected: true,
    scopePolicyVerified: true,
    authenticatedTenantResolved: true,
  };
}

export function authWorkload(service, fixture) {
  return {
    verifyBearer: async () => {
      const identity = await service.verifyBearer('Bearer ' + fixture.token);
      assert.equal(identity.subject, 'synthetic-user');
      return identity;
    },
  };
}

export function completeAuth(service, { fixture, records }) {
  const counts = service.stats();
  assert.equal(
    counts.verified,
    1 + records.reduce((total, record) => total + record.sampleCount + record.warmupIterations, 0),
  );
  assert.equal(counts.rejected, fixture.invalidTokens.length);
  assert.equal(counts.observerFailures, 0);
  return {
    actualSuccessfulVerifications: counts.verified,
    actualRejectedVerifications: counts.rejected,
    observerFailures: counts.observerFailures,
  };
}
