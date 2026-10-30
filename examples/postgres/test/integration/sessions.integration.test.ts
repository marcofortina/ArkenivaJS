// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import { sessionFixture } from './session-fixture.js';

test(
  'Session authorities reject stale, future, malformed and durably revoked primary authentication',
  { timeout: 30000 },
  async () => {
    const f = await sessionFixture();
    try {
      for (const claims of [
        { auth_time: Math.floor(Date.now() / 1000) - 61 },
        { auth_time: Math.floor(Date.now() / 1000) + 120 },
        { auth_time: 1.5 },
        { sid: '' },
      ]) {
        const a = await f.session(claims);
        await assert.rejects(
          a.run(() => f.first.sessions.create(a.identity, f.settings.defaultPolicy)),
        );
      }
      const a = await f.session(),
        issued = await a.run(() => f.first.sessions.create(a.identity, f.settings.defaultPolicy));
      await f.revokePrimary(a.subject, String(a.identity.claims.sid));
      await assert.rejects(
        a.run(() => f.second.sessions.create(a.identity, f.settings.defaultPolicy)),
      );
      await assert.rejects(f.first.sessions.validate(issued.value));
      await assert.rejects(f.second.sessions.renew(issued.value));
    } finally {
      await f.close();
    }
  },
);

test(
  'Session real signed OIDC and PostgreSQL preserve independent cookie credentials, renewal and revocation',
  { timeout: 30000 },
  async () => {
    const f = await sessionFixture();
    try {
      const a = await f.session();
      await assert.rejects(f.first.sessions.create({ ...a.identity }, f.settings.defaultPolicy));
      const issued = await a.run(() =>
        f.first.sessions.create(
          { ...a.identity, scopes: ['admin'], claims: { admin: true } },
          f.settings.defaultPolicy,
        ),
      );
      const verified = await f.second.sessions.validate(issued.value);
      assert.equal(verified.sessionId, issued.sessionId);
      assert.equal(verified.claims.admin, undefined);
      assert.equal(verified.scopes.includes('admin'), false);
      const renewed = await f.second.sessions.renew(issued.value);
      await assert.rejects(f.first.sessions.validate(issued.value));
      const next = await f.first.sessions.validate(renewed.value);
      assert.equal(next.authenticatedAt, verified.authenticatedAt);
      assert.equal(next.assuredAt, verified.assuredAt);
      await assert.rejects(f.first.sessions.revoke(renewed.sessionId));
      await a.run(() => f.first.sessions.revoke(renewed.sessionId));
      await assert.rejects(f.second.sessions.validate(renewed.value));
      const stored = await f.base.backend.app.sql.query<{ body: string }>('main', {
        text: `SELECT body FROM ${f.base.backend.schema}.security_records`,
      });
      const serialized = JSON.stringify(stored.rows);
      for (const secret of [issued.value.split('.')[2]!, renewed.value.split('.')[2]!, a.token])
        assert.equal(serialized.includes(secret), false);
    } finally {
      await f.close();
    }
  },
);
test(
  'Session global PostgreSQL epoch invalidates both replicas and stale quota rows do not block a new login',
  { timeout: 30000 },
  async () => {
    const f = await sessionFixture(1);
    try {
      const a = await f.session(),
        issued = await a.run(() => f.first.sessions.create(a.identity, f.settings.defaultPolicy));
      await assert.rejects(
        a.run(() => f.second.sessions.create(a.identity, f.settings.defaultPolicy)),
      );
      assert.equal(await a.run(() => f.second.sessions.revokeAll(a.subject)), 1);
      await assert.rejects(
        f.first.sessions.validate(issued.value),
        (error) => error instanceof KitError && error.code === 'EK_SESSION_REVOKED',
      );
      const next = await a.run(() => f.first.sessions.create(a.identity, f.settings.defaultPolicy));
      assert.equal((await f.second.sessions.validate(next.value)).sessionId, next.sessionId);
    } finally {
      await f.close();
    }
  },
);
test(
  'Session concurrent PostgreSQL renewals reach the same transaction barrier and select one replacement',
  { timeout: 30000 },
  async () => {
    const f = await sessionFixture();
    try {
      const a = await f.session(),
        issued = await a.run(() => f.first.sessions.create(a.identity, f.settings.defaultPolicy));
      f.base.synchronizeNextBatches(2);
      const results = await Promise.allSettled([
        f.first.sessions.renew(issued.value),
        f.second.sessions.renew(issued.value),
      ]);
      assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
      await assert.rejects(f.first.sessions.validate(issued.value));
      const winner = results.find((result) => result.status === 'fulfilled')!;
      assert.equal(winner.status, 'fulfilled');
      assert.equal(
        (await f.second.sessions.validate(winner.value.value)).sessionId,
        winner.value.sessionId,
      );
      const count = await f.base.backend.app.sql.queryOne<{ count: string }>('main', {
        text: `SELECT count(*)::text AS count FROM ${f.base.backend.schema}.security_records WHERE namespace='sessions.records.v1'`,
      });
      assert.equal(count?.count, '1');
    } finally {
      await f.close();
    }
  },
);
test(
  'Session tenant isolation and real secret, authority and persistence failures cannot produce identity',
  { timeout: 30000 },
  async () => {
    const f = await sessionFixture();
    try {
      const a = await f.session(),
        b = await f.session({ tenant_id: 'tenant-b', sid: 'session-b' }),
        issued = await a.run(() => f.first.sessions.create(a.identity, f.settings.defaultPolicy));
      await assert.rejects(b.run(() => f.second.sessions.revoke(issued.sessionId)));
      await assert.rejects(b.run(() => f.first.sessions.revokeAll(a.subject)));
      f.base.state.secretAvailable = false;
      await assert.rejects(f.second.sessions.validate(issued.value));
      f.base.state.secretAvailable = true;
      f.state.authorityAvailable = false;
      await assert.rejects(f.first.sessions.validate(issued.value));
      f.state.authorityAvailable = true;
      assert.equal((await f.second.sessions.validate(issued.value)).sessionId, issued.sessionId);
      await f.base.backend.app.sql.execute('main', {
        text: `DROP TABLE ${f.base.backend.schema}.security_epochs`,
      });
      await assert.rejects(f.first.sessions.validate(issued.value), (error) => {
        assert.ok(error instanceof KitError);
        assert.equal(error.code, 'EK_SESSION_STORE');
        assert.equal(error.cause, undefined);
        return true;
      });
    } finally {
      await f.close();
    }
  },
);
test(
  'Session signed backchannel logout checks issuer, subject, tenant, session and replay before global revocation',
  { timeout: 30000 },
  async () => {
    const f = await sessionFixture();
    try {
      const a = await f.session(),
        issued = await a.run(() => f.first.sessions.create(a.identity, f.settings.defaultPolicy)),
        events = { 'http://schemas.openid.net/event/backchannel-logout': {} };
      for (const claims of [
        { sid: 'wrong-session', events, jti: randomUUID() },
        { sub: 'wrong-account', events, jti: randomUUID() },
        { events, jti: randomUUID(), nonce: 'forbidden' },
        { events: { unknown: {} }, jti: randomUUID() },
        {
          events: { 'http://schemas.openid.net/event/backchannel-logout': { unexpected: true } },
          jti: randomUUID(),
        },
        { events: { 'http://schemas.openid.net/event/backchannel-logout': [] }, jti: randomUUID() },
        {
          events: { 'http://schemas.openid.net/event/backchannel-logout': null },
          jti: randomUUID(),
        },
      ])
        await assert.rejects(f.logout(await f.base.issuer.bearer(claims)));
      assert.equal((await f.first.sessions.validate(issued.value)).sessionId, issued.sessionId);
      const logout = await f.base.issuer.bearer({ events, jti: randomUUID() });
      assert.equal(await f.logout(logout), 1);
      await assert.rejects(f.second.sessions.validate(issued.value));
      f.base.rotateHmac();
      await assert.rejects(f.logout(logout));
    } finally {
      await f.close();
    }
  },
);

test(
  'Session real PostgreSQL corrupted state fails closed and restoration preserves native signed authentication',
  { timeout: 30000 },
  async () => {
    const f = await sessionFixture();
    try {
      const account = await f.session();
      const issued = await account.run(() =>
        f.first.sessions.create(account.identity, f.settings.defaultPolicy),
      );
      for (const change of ['kind', 'owner', 'epoch', 'authentication-time']) {
        const stored = await f.base.backend.app.sql.queryOne<{ body: string }>('main', {
          text: `SELECT body FROM ${f.base.backend.schema}.security_records WHERE namespace=:namespace AND id=:id`,
          bindings: { namespace: 'sessions.records.v1', id: issued.sessionId },
        });
        assert.ok(stored);
        const original = JSON.parse(stored.body) as Record<string, unknown>;
        const patch =
          change === 'kind'
            ? { kind: 'unexpected-record' }
            : change === 'owner'
              ? { ownerKey: 'g'.repeat(64) }
              : change === 'epoch'
                ? { epoch: -1 }
                : {
                    authenticatedAt: new Date(
                      Date.parse(String(original.createdAt)) + 1000,
                    ).toISOString(),
                  };
        const write = (body: string) =>
          f.base.backend.app.sql.execute('main', {
            text: `UPDATE ${f.base.backend.schema}.security_records SET body=:body WHERE namespace=:namespace AND id=:id`,
            bindings: { body, namespace: 'sessions.records.v1', id: issued.sessionId },
          });
        await write(JSON.stringify({ ...original, ...patch }));
        await assert.rejects(f.second.sessions.validate(issued.value), {
          code: 'EK_SESSION_STORE',
        });
        await write(stored.body);
        assert.equal((await f.second.sessions.validate(issued.value)).sessionId, issued.sessionId);
      }
      await account.run(() => f.first.sessions.revoke(issued.sessionId));
      await assert.rejects(f.second.sessions.validate(issued.value));
    } finally {
      await f.close();
    }
  },
);
