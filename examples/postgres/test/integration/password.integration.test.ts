// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { passwordFixture } from './password-fixture.js';

const password = () => randomBytes(24).toString('base64url');

test(
  'Password real runtime policy denies foreign authenticated tenants, disabled accounts and unavailable secrets',
  { timeout: 30000 },
  async () => {
    const f = await passwordFixture();
    try {
      const original = password(),
        a = await f.session(original),
        b = await f.session(password(), { tenant_id: 'tenant-b', sid: 'session-b' }),
        reset = await a.run(() => f.first.passwords.createReset(a.subject, a.subject));
      await assert.rejects(b.run(() => f.second.passwords.createReset(a.subject, b.subject)));
      await assert.rejects(b.run(() => f.second.passwords.consumeReset(reset.value, password())));
      await f.setEnabled(a.subject, false);
      await assert.rejects(f.first.passwords.consumeReset(reset.value, password()));
      await f.setEnabled(a.subject, true);
      f.state.secretAvailable = false;
      await assert.rejects(f.second.passwords.consumeReset(reset.value, password()));
      f.state.secretAvailable = true;
      f.state.authorityAvailable = false;
      await assert.rejects(f.first.passwords.consumeReset(reset.value, password()));
      f.state.authorityAvailable = true;
      await f.sessions.revokePrimary(a.subject, String(a.identity.claims.sid));
      await assert.rejects(a.run(() => f.first.passwords.createReset(a.subject, a.subject)));
      assert.equal(
        (await f.first.passwords.verify(original, await f.current(a.subject))).valid,
        true,
      );
      await f.second.passwords.consumeReset(reset.value, password());
    } finally {
      await f.close();
    }
  },
);

test(
  'Password unavailable session persistence rolls back the credential update and reset deletion',
  { timeout: 30000 },
  async () => {
    const f = await passwordFixture();
    try {
      const original = password(),
        a = await f.session(original),
        reset = await a.run(() => f.first.passwords.createReset(a.subject, a.subject));
      await f.base.backend.app.sql.execute('main', {
        text: `DROP TABLE ${f.base.backend.schema}.security_epochs`,
      });
      await assert.rejects(f.second.passwords.consumeReset(reset.value, password()));
      assert.equal(
        (await f.first.passwords.verify(original, await f.current(a.subject))).valid,
        true,
      );
      assert.ok(await f.settings.resetStore.store.read('password.resets.v1', reset.requestId));
    } finally {
      await f.close();
    }
  },
);

test(
  'Password reset uses one real PostgreSQL transaction to replace credentials, consume the token and revoke sessions',
  { timeout: 30000 },
  async () => {
    const f = await passwordFixture();
    try {
      const original = password(),
        a = await f.session(original),
        session = await a.run(() =>
          f.sessions.first.sessions.create(a.identity, f.sessions.settings.defaultPolicy),
        ),
        reset = await a.run(() => f.first.passwords.createReset(a.subject, a.subject)),
        next = password();
      await f.second.passwords.consumeReset(reset.value, next);
      const current = await f.current(a.subject);
      assert.equal((await f.first.passwords.verify(next, current)).valid, true);
      assert.equal((await f.second.passwords.verify(original, current)).valid, false);
      await assert.rejects(f.sessions.first.sessions.validate(session.value));
      await assert.rejects(f.sessions.second.sessions.validate(session.value));
      await assert.rejects(f.first.passwords.consumeReset(reset.value, password()));
    } finally {
      await f.close();
    }
  },
);
test(
  'Password real PostgreSQL rollback preserves the previous password, reset and existing session',
  { timeout: 30000 },
  async () => {
    const f = await passwordFixture();
    try {
      const original = password(),
        a = await f.session(original),
        session = await a.run(() =>
          f.sessions.first.sessions.create(a.identity, f.sessions.settings.defaultPolicy),
        ),
        reset = await a.run(() => f.first.passwords.createReset(a.subject, a.subject));
      f.state.failAfterPasswordWrite = true;
      await assert.rejects(f.second.passwords.consumeReset(reset.value, password()));
      assert.equal(
        (await f.first.passwords.verify(original, await f.current(a.subject))).valid,
        true,
      );
      assert.equal(
        (await f.sessions.second.sessions.validate(session.value)).sessionId,
        session.sessionId,
      );
      f.state.failAfterPasswordWrite = false;
      await f.first.passwords.consumeReset(reset.value, password());
      await assert.rejects(f.sessions.second.sessions.validate(session.value));
    } finally {
      await f.close();
    }
  },
);
test(
  'Password real concurrent reset consumers contend on the same SQL row and replace the credential once',
  { timeout: 30000 },
  async () => {
    const f = await passwordFixture();
    try {
      const a = await f.session(password()),
        reset = await a.run(() => f.first.passwords.createReset(a.subject, a.subject)),
        x = password(),
        y = password();
      f.synchronizeCommits(2);
      const results = await Promise.allSettled([
        f.first.passwords.consumeReset(reset.value, x),
        f.second.passwords.consumeReset(reset.value, y),
      ]);
      assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
      const current = await f.current(a.subject);
      assert.equal(
        (await f.first.passwords.verify(x, current)).valid,
        results[0]!.status === 'fulfilled',
      );
      assert.equal(
        (await f.second.passwords.verify(y, current)).valid,
        results[1]!.status === 'fulfilled',
      );
    } finally {
      await f.close();
    }
  },
);
