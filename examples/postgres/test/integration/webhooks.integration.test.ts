// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { webhooksFixture } from './webhooks-fixture.js';
import type { WebhookContext } from '@arkenivajs/webhooks';

const context = (): WebhookContext => ({
  destinationId: 'receiver',
  eventId: 'one',
  keyId: 'one',
  timestamp: new Date().toISOString(),
  nonce: randomBytes(24).toString('base64url'),
});
const body = Buffer.from('{"type":"fixture.event","private":"owned-webhook-body"}');

test(
  'Webhook independently authenticated replicas contend on one real PostgreSQL nonce and persist only its digest',
  { timeout: 30000 },
  async () => {
    const f = await webhooksFixture();
    try {
      const a = await f.session(),
        ctx = context();
      await assert.rejects(f.first.webhooks.sign(body, 'fixture/webhooks', ctx), {
        code: 'EK_AUTH_FORBIDDEN',
      });
      const signature = await a.run(() => f.first.webhooks.sign(body, 'fixture/webhooks', ctx));
      const results = await Promise.allSettled([
        a.run(() => f.first.webhooks.verify(body, signature, ctx)),
        a.run(() => f.second.webhooks.verify(body, signature, ctx)),
      ]);
      assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
      assert.equal(
        results.filter(
          (result) => result.status === 'rejected' && result.reason.code === 'EK_WEBHOOK_REPLAY',
        ).length,
        1,
      );
      const stored = await f.backend.app.sql.query<{ digest: string; namespace: string }>('main', {
        text: `SELECT digest, namespace FROM ${f.backend.schema}.security_claims WHERE namespace='webhooks.nonces.v1'`,
      });
      assert.equal(stored.rows.length, 1);
      assert.match(stored.rows[0]!.digest, /^[a-f0-9]{64}$/);
      const serialized = JSON.stringify(stored.rows);
      for (const value of [ctx.nonce, signature.signature, a.token, 'owned-webhook-body'])
        assert.equal(serialized.includes(value), false);
      await f.first.app.stop();
      const restarted = await f.instance();
      await assert.rejects(
        a.run(() => restarted.webhooks.verify(body, signature, ctx)),
        { code: 'EK_WEBHOOK_REPLAY' },
      );
    } finally {
      await f.close();
    }
  },
);

test(
  'Webhook real OIDC tenant isolation, revocation and secret outages reject before consuming the valid PostgreSQL nonce',
  { timeout: 30000 },
  async () => {
    const f = await webhooksFixture();
    try {
      const a = await f.session(),
        b = await f.session({ tenant_id: 'tenant-b', sid: 'other-primary' }),
        ctx = context(),
        signature = await a.run(() => f.first.webhooks.sign(body, 'fixture/webhooks', ctx));
      await assert.rejects(
        b.run(() => f.second.webhooks.verify(body, signature, ctx)),
        { code: 'EK_WEBHOOK_SIGNATURE' },
      );
      f.state.secretAvailable = false;
      await assert.rejects(
        a.run(() => f.second.webhooks.verify(body, signature, ctx)),
        { code: 'EK_WEBHOOK_SIGNATURE' },
      );
      f.state.secretAvailable = true;
      await f.primary.revokePrimary(a.subject, String(a.identity.claims.sid));
      await assert.rejects(
        a.run(() => f.second.webhooks.verify(body, signature, ctx)),
        { code: 'EK_AUTH_FORBIDDEN' },
      );
      const count = await f.backend.app.sql.queryOne<{ count: string }>('main', {
        text: `SELECT count(*)::text AS count FROM ${f.backend.schema}.security_claims WHERE namespace='webhooks.nonces.v1'`,
      });
      assert.equal(count?.count, '0');
    } finally {
      await f.close();
    }
  },
);

test(
  'Webhook unavailable PostgreSQL persistence produces no verified result and has no in-memory replay fallback',
  { timeout: 30000 },
  async () => {
    const f = await webhooksFixture();
    try {
      const a = await f.session(),
        ctx = context(),
        signature = await a.run(() => f.first.webhooks.sign(body, 'fixture/webhooks', ctx));
      await f.backend.app.sql.execute('main', {
        text: `DROP TABLE ${f.backend.schema}.security_claims`,
      });
      await assert.rejects(
        a.run(() => f.second.webhooks.verify(body, signature, ctx)),
        (error: unknown) => {
          assert.equal((error as { code: string }).code, 'EK_WEBHOOK_REPLAY');
          assert.equal((error as { details: { outcome: string } }).details.outcome, 'unknown');
          assert.equal((error as Error).cause, undefined);
          return true;
        },
      );
    } finally {
      await f.close();
    }
  },
);
