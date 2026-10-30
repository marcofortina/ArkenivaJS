// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

const domain = 'arkenivajs.sessions.verifier.v1',
  records = 'sessions.records.v1';
const ownerParts = (owner) => [owner.issuer, owner.subject, owner.tenant?.tenantId ?? ''];

export function sessionMacParts(state, secret) {
  return [
    ...ownerParts(state.subject),
    state.id,
    secret,
    String(state.epoch),
    state.authenticatedAt,
    state.assuredAt ?? '',
    state.identity.assurance ?? 'single-factor',
    state.createdAt,
    state.lastSeenAt,
    state.absoluteExpiresAt,
    state.expiresAt,
    String(state.policy.absoluteTtlMs),
    String(state.policy.idleTtlMs),
    String(state.policy.maxConcurrentSessions),
    state.policy.cookieSameSite ?? 'lax',
  ];
}

export function sessionsPorts(fixture) {
  const url = new URL(fixture.endpoint);
  assert.equal(url.protocol, 'http:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.ok(url.port && !url.username && !url.password && !url.search && !url.hash);
  assert.equal(url.pathname, '/provider');
  const exchange = async (method, args) => {
    const response = await globalThis.fetch(url, {
      method: 'POST',
      headers: { authorization: 'Bearer ' + fixture.bearer, 'content-type': 'application/json' },
      body: JSON.stringify({ method, args }),
      signal: AbortSignal.timeout(5000),
      redirect: 'error',
    });
    assert.equal(response.status, 200);
    const body = await response.text();
    assert.ok(Buffer.byteLength(body) <= 32768);
    return JSON.parse(body).result;
  };
  const deny = async () => {
    throw new Error('The session comparison exposes only scoped validation state operations');
  };
  return {
    exchange,
    store: {
      read: (...args) => exchange('read', args.slice(0, 2)),
      compareAndSet: (...args) => exchange('compareAndSet', args.slice(0, 4)),
      currentOwnerEpoch: (...args) => exchange('currentOwnerEpoch', args.slice(0, 2)),
      ...Object.fromEntries(
        ['claimOnce', 'atomicBatch', 'listByOwner', 'bumpOwnerEpoch'].map((name) => [name, deny]),
      ),
    },
    hmac: {
      algorithm: 'HMAC-SHA256',
      usage: 'test-only',
      digest: (name, parts, ref) => exchange('digest', [name, parts, ref]),
      verify: (name, parts, expected, ref) => exchange('verify', [name, parts, expected, ref]),
    },
    authority: {
      usage: 'test-only',
      require: (...args) => exchange('authorize', args.slice(0, 3)),
      resolveIdentity: (...args) => exchange('resolve', args.slice(0, 2)),
    },
  };
}

export function sessionsSettings(fixture) {
  const ports = sessionsPorts(fixture);
  return {
    store: { store: ports.store, securityLevel: 'test-only', operationTimeoutMs: 5000 },
    hmac: ports.hmac,
    hmacKeyRef: fixture.keyRef,
    authority: ports.authority,
    defaultPolicy: { absoluteTtlMs: 600000, idleTtlMs: 300000, cookieSameSite: 'lax' },
    maxSessionsPerSubject: 16,
  };
}

/** Benchmark-only valid-session reference uses the same external HMAC, account authority and SQL refresh. */
export async function nativeSessions(fixture) {
  const { store, hmac, authority } = sessionsPorts(fixture);
  await hmac.digest(
    domain,
    ['negative', randomUUID(), randomBytes(32).toString('base64url')],
    fixture.keyRef,
  );
  const index = async (name, parts) =>
    createHash('sha256')
      .update(await hmac.digest(name, parts, fixture.keyRef))
      .digest('hex');
  const rateOwner = await index('arkenivajs.sessions.rate-owner.v1', ['verification']);
  async function reserve() {
    const minute = Math.floor(Date.now() / 60000),
      id = 'verify-' + rateOwner + ':' + minute;
    for (let attempt = 0; attempt < 8; attempt++) {
      const previous = await store.read('sessions.attempts.v1', id),
        count = previous?.count ?? 0;
      assert.ok(count < 10000);
      if (
        (
          await store.compareAndSet('sessions.attempts.v1', id, previous?.version ?? null, {
            kind: 'session-attempts-v1',
            ownerKey: rateOwner,
            minute,
            count: count + 1,
            expiresAt: new Date((minute + 2) * 60000).toISOString(),
          })
        ).committed
      )
        return;
    }
    throw new Error('The native session attempt budget could not be reserved');
  }
  return {
    async validate(token) {
      const match = /^ss1\.([a-f0-9-]{36})\.([A-Za-z0-9_-]{43})$/.exec(token);
      assert.ok(match);
      const [, id, secret] = match,
        activity = Date.now();
      await reserve();
      for (let view = 0; view < 2; view++) {
        const previous = await store.read(records, id);
        assert.ok(previous && previous.kind === 'session-v1');
        assert.equal(
          await hmac.verify(
            domain,
            sessionMacParts(previous, secret),
            previous.digest,
            fixture.keyRef,
          ),
          true,
        );
        assert.ok(Date.parse(previous.expiresAt) > Date.now());
        assert.equal(
          await store.currentOwnerEpoch('sessions.epochs.v1', previous.ownerKey),
          previous.epoch,
        );
        const auth = await authority.resolveIdentity(previous.identity, {
          operation: 'validate',
          sessionId: id,
        });
        assert.equal(auth.authenticatedAt, previous.authenticatedAt);
        assert.equal(auth.assuredAt, previous.assuredAt);
        assert.equal(auth.identity.assurance, previous.identity.assurance);
        const subject = await authority.require('sessions.validate', auth.subject, {
          tenant: auth.subject.tenant,
          sessionId: id,
          sessionPolicy: previous.policy,
          assurance: auth.identity.assurance,
        });
        assert.equal(
          await index('arkenivajs.sessions.owner.v1', ownerParts(subject)),
          previous.ownerKey,
        );
        let expiresAt = previous.expiresAt;
        if (Date.parse(previous.lastSeenAt) < activity) {
          const now = Date.now();
          assert.ok(Date.parse(previous.absoluteExpiresAt) > now);
          const { version, digest: oldDigest, ...fields } = previous;
          assert.equal(typeof oldDigest, 'string');
          const next = {
            ...fields,
            lastSeenAt: new Date(now).toISOString(),
            expiresAt: new Date(
              Math.min(Date.parse(previous.absoluteExpiresAt), now + previous.policy.idleTtlMs),
            ).toISOString(),
          };
          next.digest = await hmac.digest(domain, sessionMacParts(next, secret), fixture.keyRef);
          if (!(await store.compareAndSet(records, id, version, next)).committed) continue;
          expiresAt = next.expiresAt;
        } else {
          const fresh = await store.read(records, id);
          if (!fresh || fresh.version !== previous.version) continue;
        }
        assert.equal(
          await store.currentOwnerEpoch('sessions.epochs.v1', previous.ownerKey),
          previous.epoch,
        );
        return {
          ...auth.identity,
          sessionId: id,
          authenticatedAt: previous.authenticatedAt,
          ...(previous.assuredAt ? { assuredAt: previous.assuredAt } : {}),
          expiresAt,
        };
      }
      throw new Error('The native session refresh retry budget was exhausted');
    },
  };
}

export async function verifySessions(service, fixture) {
  const grant = await sessionsPorts(fixture).exchange('grant', []);
  const first = await service.validate(grant.token);
  assert.equal(first.sessionId, grant.sessionId);
  assert.equal(first.authenticatedAt, grant.authenticatedAt);
  assert.equal(first.assuredAt, grant.assuredAt);
  assert.equal(first.assurance, 'mfa');
  const parts = grant.token.split('.');
  parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
  await assert.rejects(service.validate(parts.join('.')));
  const second = await service.validate(grant.token);
  assert.equal(second.authenticatedAt, first.authenticatedAt);
  assert.equal(second.assuredAt, first.assuredAt);
  assert.equal(second.assurance, first.assurance);
  assert.equal(second.subject, first.subject);
  assert.equal(second.issuer, first.issuer);
  assert.ok(Date.parse(second.expiresAt) >= Date.parse(first.expiresAt));
  return {
    actualValidationsVerified: 2,
    wrongSecretRejected: true,
    originalAuthenticationTimePreserved: true,
    originalMfaTimePreserved: true,
    assuranceUnchanged: true,
    idleRefreshVerified: true,
  };
}
