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
  const protocol = {
    resolved: 0,
    authorized: 0,
    verified: 0,
    rejectedMacs: 0,
    ownerDigests: 0,
    rateOwnerDigests: 0,
    verifierDigests: 0,
    epochs: 0,
    recordReads: 0,
    activityCasAttempts: 0,
    attemptReads: 0,
    attemptCasAttempts: 0,
    committedAttempts: 0,
    providerFailures: 0,
  };
  const attemptRows = new Map();
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
            protocol.resolved++;
          } else {
            assert.equal(args[0], 'sessions.validate');
            assert.ok(originals.has(args[2].sessionId));
            result = await backend.settings.authority.require(...args);
            protocol.authorized++;
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
          if (method === 'digest') {
            remember(result);
            protocol[
              args[0] === 'arkenivajs.sessions.owner.v1'
                ? 'ownerDigests'
                : args[0] === 'arkenivajs.sessions.rate-owner.v1'
                  ? 'rateOwnerDigests'
                  : 'verifierDigests'
            ]++;
          } else {
            protocol.verified++;
            if (result === false) protocol.rejectedMacs++;
          }
        } else {
          assert.equal(faults.store, false);
          if (method === 'currentOwnerEpoch') {
            assert.equal(args[0], 'sessions.epochs.v1');
            assert.equal(args.length, 2);
            result = await backend.base.backend.store.currentOwnerEpoch(...args);
            protocol.epochs++;
          } else {
            assert.ok(['sessions.records.v1', 'sessions.attempts.v1'].includes(args[0]));
            assert.equal(typeof args[1], 'string');
            assert.ok(args[1].length <= 256);
            if (method === 'read') {
              assert.equal(args.length, 2);
              result = await backend.base.backend.store.read(...args);
              if (args[0] === 'sessions.records.v1') protocol.recordReads++;
              else {
                protocol.attemptReads++;
                if (!attemptRows.has(args[1]))
                  attemptRows.set(args[1], { initial: result?.count ?? 0, committed: 0 });
              }
            } else {
              assert.equal(method, 'compareAndSet');
              assert.equal(args.length, 4);
              if (args[0] === 'sessions.records.v1') assert.ok(originals.has(args[1]));
              result = await backend.base.backend.store.compareAndSet(...args);
              if (args[0] === 'sessions.records.v1') {
                protocol.activityCasAttempts++;
                if (result.committed) state.committedActivityUpdates++;
              } else {
                protocol.attemptCasAttempts++;
                if (result.committed) {
                  assert.ok(attemptRows.has(args[1]));
                  attemptRows.get(args[1]).committed++;
                  protocol.committedAttempts++;
                }
              }
            }
          }
        }
        response
          .writeHead(200, { 'content-type': 'application/json' })
          .end(JSON.stringify({ result }));
      })()
        .catch(() => {
          protocol.providerFailures++;
          response.writeHead(400).end();
        })
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
      async verify(expectedRefreshed, expectedValidations) {
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
        let observation;
        if (expectedValidations !== undefined) {
          assert.ok(Number.isSafeInteger(expectedValidations) && expectedValidations >= 8);
          const rejected = grants.length,
            total = expectedValidations + rejected;
          assert.equal(state.handedOut, grants.length);
          assert.equal(protocol.providerFailures, 0);
          assert.equal(protocol.resolved, expectedValidations);
          assert.equal(protocol.authorized, expectedValidations);
          assert.equal(protocol.ownerDigests, expectedValidations);
          assert.equal(protocol.rateOwnerDigests, grants.length);
          assert.equal(protocol.verified, total);
          assert.equal(protocol.rejectedMacs, rejected);
          assert.equal(protocol.epochs, 2 * expectedValidations);
          assert.equal(protocol.attemptReads, total);
          assert.equal(protocol.attemptCasAttempts, total);
          assert.equal(protocol.committedAttempts, total);
          assert.equal(protocol.activityCasAttempts, state.committedActivityUpdates);
          assert.ok(state.committedActivityUpdates <= expectedValidations);
          assert.equal(protocol.verifierDigests, grants.length + state.committedActivityUpdates);
          assert.equal(
            protocol.recordReads,
            2 * expectedValidations + rejected - state.committedActivityUpdates,
          );
          let persistedAttemptDelta = 0;
          for (const [id, baseline] of attemptRows) {
            const actual = await backend.base.backend.store.read('sessions.attempts.v1', id);
            assert.equal(actual.count, baseline.initial + baseline.committed);
            persistedAttemptDelta += actual.count - baseline.initial;
          }
          assert.equal(persistedAttemptDelta, total);
          observation = {
            successfulValidations: expectedValidations,
            rejectedWrongSecrets: rejected,
            persistedAttemptDelta,
            persistedAttemptRows: attemptRows.size,
            protocol: { ...protocol },
            activityPolicy:
              'CAS only when the trusted clock advances activity; unchanged authentication/MFA times and absolute expiry are independently verified',
          };
        }
        return {
          persistedRefreshedSessions: refreshed,
          committedActivityUpdates: state.committedActivityUpdates,
          originalAuthenticationAndMfaTimesPreserved: true,
          persistedHmacsVerified: true,
          ...(observation ? { observation } : {}),
          releaseGate: false,
        };
      },
    };
  } catch (cause) {
    await close();
    throw cause;
  }
}
