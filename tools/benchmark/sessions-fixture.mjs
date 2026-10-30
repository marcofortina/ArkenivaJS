// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { sessionFixture } from '../../examples/postgres/dist-test/integration/session-fixture.js';
import { sessionMacParts } from './sessions-workload.mjs';

/** Parent-owned signed authentication events and external keys back actual PostgreSQL session activity. */
export async function startSessionsFixture() {
  assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
  const backend = await sessionFixture(16);
  const bearer = randomBytes(32).toString('base64url'),
    grants = [],
    originals = new Map(),
    tasks = new Set();
  const privacyValues = [bearer, '127.0.0.1'],
    faults = { store: false, hmac: false, authority: false };
  const state = { handedOut: 0, committedActivityUpdates: 0 };
  let bridge;
  const remember = (value) => {
    if (typeof value === 'string' && value.length > 0 && !privacyValues.includes(value))
      privacyValues.push(value);
  };
  const close = async () => {
    try {
      if (bridge?.listening) {
        bridge.closeAllConnections();
        await new Promise((done) => bridge.close(done));
      }
      await Promise.allSettled([...tasks]);
    } finally {
      await backend.close();
    }
  };
  try {
    const primary = await backend.session({ acr: 'urn:fixture:mfa' });
    for (const value of [
      primary.subject.issuer,
      primary.subject.subject,
      primary.subject.tenant.tenantId,
    ])
      remember(value);
    for (let index = 0; index < 4; index++) {
      const issued = await primary.run(() =>
        backend.first.sessions.create(primary.identity, {
          absoluteTtlMs: 600000,
          idleTtlMs: 300000,
          cookieSameSite: 'lax',
        }),
      );
      const record = await backend.base.backend.store.read('sessions.records.v1', issued.sessionId);
      assert.equal(record.identity.assurance, 'mfa');
      assert.ok(record.assuredAt);
      grants.push({
        token: issued.value,
        sessionId: issued.sessionId,
        authenticatedAt: record.authenticatedAt,
        assuredAt: record.assuredAt,
      });
      originals.set(issued.sessionId, record);
      for (const value of [
        issued.value,
        issued.value.split('.')[2],
        issued.sessionId,
        record.digest,
        record.ownerKey,
      ])
        remember(value);
    }
    bridge = createServer((request, response) => {
      const task = (async () => {
        assert.equal(request.method, 'POST');
        assert.equal(request.url, '/provider');
        const supplied = Buffer.from(request.headers.authorization ?? ''),
          expected = Buffer.from('Bearer ' + bearer);
        assert.equal(supplied.length, expected.length);
        assert.ok(timingSafeEqual(supplied, expected));
        const chunks = [];
        let bytes = 0;
        for await (const chunk of request) {
          bytes += chunk.length;
          assert.ok(bytes <= 65536);
          chunks.push(chunk);
        }
        const { method, args } = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        assert.ok(Array.isArray(args));
        let result;
        if (method === 'grant') {
          assert.equal(args.length, 0);
          assert.ok(state.handedOut < grants.length);
          result = grants[state.handedOut++];
        } else if (method === 'resolve' || method === 'authorize') {
          assert.equal(faults.authority, false);
          if (method === 'resolve') {
            assert.equal(args[1].operation, 'validate');
            assert.ok(originals.has(args[1].sessionId));
            result = await backend.settings.authority.resolveIdentity(...args);
          } else {
            assert.equal(args[0], 'sessions.validate');
            assert.ok(originals.has(args[2].sessionId));
            result = await backend.settings.authority.require(...args);
          }
        } else if (method === 'digest' || method === 'verify') {
          assert.equal(faults.hmac, false);
          assert.ok(
            [
              'arkenivajs.sessions.verifier.v1',
              'arkenivajs.sessions.owner.v1',
              'arkenivajs.sessions.rate-owner.v1',
            ].includes(args[0]),
          );
          assert.ok(Array.isArray(args[1]) && args[1].length <= 20);
          for (const part of args[1]) {
            assert.equal(typeof part, 'string');
            assert.ok(part.length <= 2048);
            if (part.length >= 32) remember(part);
          }
          assert.equal(args[method === 'digest' ? 2 : 3], backend.settings.hmacKeyRef);
          if (method === 'verify') remember(args[2]);
          result = await backend.settings.hmac[method](...args);
          if (method === 'digest') remember(result);
        } else {
          assert.equal(faults.store, false);
          if (method === 'currentOwnerEpoch') {
            assert.equal(args[0], 'sessions.epochs.v1');
            assert.equal(args.length, 2);
            result = await backend.base.backend.store.currentOwnerEpoch(...args);
          } else {
            assert.ok(['sessions.records.v1', 'sessions.attempts.v1'].includes(args[0]));
            assert.equal(typeof args[1], 'string');
            assert.ok(args[1].length <= 256);
            if (method === 'read') {
              assert.equal(args.length, 2);
              result = await backend.base.backend.store.read(...args);
            } else {
              assert.equal(method, 'compareAndSet');
              assert.equal(args.length, 4);
              if (args[0] === 'sessions.records.v1') assert.ok(originals.has(args[1]));
              result = await backend.base.backend.store.compareAndSet(...args);
              if (args[0] === 'sessions.records.v1' && result.committed)
                state.committedActivityUpdates++;
            }
          }
        }
        response
          .writeHead(200, { 'content-type': 'application/json' })
          .end(JSON.stringify({ result }));
      })()
        .catch(() => response.writeHead(400).end())
        .finally(() => tasks.delete(task));
      tasks.add(task);
    });
    await new Promise((done, reject) => {
      bridge.once('error', reject);
      bridge.listen(0, '127.0.0.1', done);
    });
    const fixture = {
      endpoint: 'http://127.0.0.1:' + bridge.address().port + '/provider',
      bearer,
      keyRef: backend.settings.hmacKeyRef,
    };
    privacyValues.push(...Object.values(fixture));
    return {
      fixture,
      privacyValues,
      close,
      fault(name, value) {
        assert.ok(Object.hasOwn(faults, name));
        faults[name] = value;
      },
      async revokeOwner() {
        const owner = originals.values().next().value;
        return backend.base.backend.store.bumpOwnerEpoch('sessions.epochs.v1', owner.ownerKey);
      },
      async verify(expectedRefreshed) {
        let refreshed = 0;
        for (const grant of grants) {
          const record = await backend.base.backend.store.read(
              'sessions.records.v1',
              grant.sessionId,
            ),
            original = originals.get(grant.sessionId);
          assert.equal(record.authenticatedAt, original.authenticatedAt);
          assert.equal(record.assuredAt, original.assuredAt);
          assert.equal(record.identity.assurance, original.identity.assurance);
          assert.equal(record.absoluteExpiresAt, original.absoluteExpiresAt);
          assert.equal(record.createdAt, original.createdAt);
          assert.equal(
            await backend.settings.hmac.verify(
              'arkenivajs.sessions.verifier.v1',
              sessionMacParts(record, grant.token.split('.')[2]),
              record.digest,
              backend.settings.hmacKeyRef,
            ),
            true,
          );
          if (record.version !== original.version) {
            assert.ok(Date.parse(record.lastSeenAt) > Date.parse(original.lastSeenAt));
            refreshed++;
          }
        }
        assert.equal(refreshed, expectedRefreshed);
        assert.ok(state.committedActivityUpdates >= expectedRefreshed);
        return {
          persistedRefreshedSessions: refreshed,
          committedActivityUpdates: state.committedActivityUpdates,
          originalAuthenticationAndMfaTimesPreserved: true,
          persistedHmacsVerified: true,
          releaseGate: false,
        };
      },
    };
  } catch (cause) {
    await close();
    throw cause;
  }
}
