// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { magicLinkFixture } from './magiclink-fixture.js';

test(
  'Real PostgreSQL and signed account authority enforce one-use magic link redemption across instances',
  { timeout: 30000 },
  async () => {
    const f = await magicLinkFixture();
    try {
      const account = await f.session();
      await assert.rejects(f.first.magic.issue({ ...account.subject }, 'login'), {
        code: 'EK_MAGICLINK_INVALID',
      });
      const issued = await account.run(() => f.first.magic.issue(account.subject, 'login'));
      const results = await Promise.allSettled([
        f.first.magic.consume(issued.value, { method: 'POST', purpose: 'login' }),
        f.second.magic.consume(issued.value, { method: 'POST', purpose: 'login' }),
      ]);
      const successes = results.filter((result) => result.status === 'fulfilled');
      assert.equal(successes.length, 1);
      assert.equal(results.filter((result) => result.status === 'rejected').length, 1);
      if (successes[0]?.status === 'fulfilled')
        assert.equal(f.base.auth.isVerifiedTenant(successes[0].value.subject.tenant), true);
      const stored = await f.base.backend.app.sql.query<{ body: string }>('main', {
        text: `SELECT body FROM ${f.base.backend.schema}.security_records`,
      });
      const serialized = JSON.stringify(stored.rows);
      for (const sensitive of [
        issued.value,
        issued.value.split('.')[2]!,
        issued.redemptionUrl,
        account.token,
      ])
        assert.ok(!serialized.includes(sensitive));
    } finally {
      await f.close();
    }
  },
);
test(
  'Real signed tenant isolation, account disablement, provider outage and revocation fail closed',
  { timeout: 30000 },
  async () => {
    const f = await magicLinkFixture();
    try {
      const a = await f.session({ tenant_id: 'tenant-a' }),
        b = await f.session({ tenant_id: 'tenant-b' });
      const issued = await b.run(() => f.first.magic.issue(b.subject, 'account-recover'));
      await assert.rejects(
        a.run(() =>
          f.second.magic.consume(issued.value, { method: 'POST', purpose: 'account-recover' }),
        ),
        { code: 'EK_MAGICLINK_INVALID' },
      );
      await assert.rejects(
        a.run(() => f.first.magic.revoke(issued.issueId)),
        { code: 'EK_MAGICLINK_INVALID' },
      );
      f.base.state.accountEnabled = false;
      await assert.rejects(
        f.second.magic.consume(issued.value, { method: 'POST', purpose: 'account-recover' }),
        { code: 'EK_MAGICLINK_INVALID' },
      );
      f.base.state.accountEnabled = true;
      f.base.state.secretAvailable = false;
      await assert.rejects(
        f.second.magic.consume(issued.value, { method: 'POST', purpose: 'account-recover' }),
        { code: 'EK_BACKEND_UNAVAILABLE' },
      );
      f.base.state.secretAvailable = true;
      await b.run(() => f.first.magic.revoke(issued.issueId));
      await assert.rejects(
        f.second.magic.consume(issued.value, { method: 'POST', purpose: 'account-recover' }),
        { code: 'EK_MAGICLINK_REPLAY' },
      );
    } finally {
      await f.close();
    }
  },
);
test(
  'Native version-aware HMAC rotation and shared PostgreSQL quotas preserve pending magic links',
  { timeout: 30000 },
  async () => {
    const f = await magicLinkFixture(1);
    try {
      const account = await f.session(),
        issued = await account.run(() => f.first.magic.issue(account.subject, 'email-verify'));
      f.base.rotateHmac();
      await assert.rejects(
        account.run(() => f.second.magic.issue(account.subject, 'email-verify')),
        { code: 'EK_MAGICLINK_INVALID' },
      );
      await assert.rejects(
        f.second.magic.consume(issued.value, { method: 'GET' as 'POST', purpose: 'email-verify' }),
        { code: 'EK_CONFIG_INVALID' },
      );
      await assert.rejects(
        f.second.magic.consume(issued.value, { method: 'POST', purpose: 'login' }),
        { code: 'EK_MAGICLINK_INVALID' },
      );
      assert.equal(
        (await f.second.magic.consume(issued.value, { method: 'POST', purpose: 'email-verify' }))
          .intent,
        'email-verify',
      );
    } finally {
      await f.close();
    }
  },
);

test(
  'Magic link real PostgreSQL corrupted state cannot grant an identity or consume the restored single-use credential',
  { timeout: 30000 },
  async () => {
    const f = await magicLinkFixture(1000);
    try {
      const account = await f.session();
      const issued = await account.run(() => f.first.magic.issue(account.subject, 'login'));
      const stored = await f.base.backend.app.sql.queryOne<{ body: string; version: string }>(
        'main',
        {
          text: `SELECT body,version::text AS version FROM ${f.base.backend.schema}.security_records WHERE namespace=:namespace AND id=:id`,
          bindings: { namespace: 'magiclink.records.v1', id: issued.issueId },
        },
      );
      assert.ok(stored);
      const original = JSON.parse(stored.body) as Record<string, unknown>;
      const write = (body: string) =>
        f.base.backend.app.sql.execute('main', {
          text: `UPDATE ${f.base.backend.schema}.security_records SET body=:body WHERE namespace=:namespace AND id=:id`,
          bindings: { body, namespace: 'magiclink.records.v1', id: issued.issueId },
        });
      for (const patch of [
        { kind: 'unexpected-record' },
        { state: 'unexpected-state' },
        { ownerKey: 'g'.repeat(64) },
        { validUntil: 'invalid' },
      ]) {
        await write(JSON.stringify({ ...original, ...patch }));
        await assert.rejects(
          f.second.magic.consume(issued.value, { method: 'POST', purpose: 'login' }),
          { code: 'EK_BACKEND_UNAVAILABLE' },
        );
        await write(stored.body);
        const current = await f.base.backend.app.sql.queryOne<{ version: string }>('main', {
          text: `SELECT version::text AS version FROM ${f.base.backend.schema}.security_records WHERE namespace=:namespace AND id=:id`,
          bindings: { namespace: 'magiclink.records.v1', id: issued.issueId },
        });
        assert.equal(current?.version, stored.version);
      }
      assert.equal(
        (await f.second.magic.consume(issued.value, { method: 'POST', purpose: 'login' })).subject
          .subject,
        account.subject.subject,
      );
      await assert.rejects(
        f.first.magic.consume(issued.value, { method: 'POST', purpose: 'login' }),
        { code: 'EK_MAGICLINK_REPLAY' },
      );
    } finally {
      await f.close();
    }
  },
);
