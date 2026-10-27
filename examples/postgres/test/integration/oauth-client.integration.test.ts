// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { oauthFixture } from './oauth-client-fixture.js';

test(
  'OAuth verified HTTPS PKCE state is consumed once across separate PostgreSQL pools and refresh survives application restart',
  { timeout: 30000 },
  async () => {
    const f = await oauthFixture();
    try {
      const account = await f.session(),
        start = await account.run(() =>
          f.first.oauth.beginAuthorization({
            audience: f.metadata.audience,
            scopes: ['openid', 'orders.read'],
            returnPath: '/orders',
          }),
        );
      const callback = await f.authorize(start.authorizationUrl),
        results = await account.run(() =>
          Promise.allSettled([
            f.first.oauth.exchangeCode(callback),
            f.second.oauth.exchangeCode(callback),
          ]),
        );
      assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
      const winner = results.find((result) => result.status === 'fulfilled');
      assert.ok(winner && winner.status === 'fulfilled');
      assert.ok(winner.value.refreshRef);
      const rows = await f.backend.app.sql.query<{ body: string }>('main', {
        text: `SELECT body FROM ${f.backend.schema}.security_records WHERE namespace LIKE 'oauth.%'`,
      });
      const serialized = JSON.stringify(rows.rows);
      for (const secret of [
        f.metadata.clientSecret,
        winner.value.accessToken,
        winner.value.refreshRef,
        start.stateRef,
        new URL(start.authorizationUrl).searchParams.get('nonce')!,
      ])
        assert.equal(serialized.includes(secret), false);
      await f.first.app.stop();
      const restarted = await f.instance();
      const next = await account.run(() => restarted.oauth.refresh(winner.value.refreshRef!));
      assert.ok(next.refreshRef);
      assert.notEqual(next.refreshRef, winner.value.refreshRef);
      await account.run(() => f.second.oauth.revoke(next.refreshRef!));
      await assert.rejects(account.run(() => restarted.oauth.refresh(next.refreshRef!)));
    } finally {
      await f.close();
    }
  },
);
test(
  'OAuth durable refresh races, spent-token replay and tenant policy cannot issue a second grant',
  { timeout: 30000 },
  async () => {
    const f = await oauthFixture();
    try {
      const account = await f.session(),
        foreign = await f.session({ tenant_id: 'tenant-b', sid: 'oauth-foreign-session' });
      const start = await account.run(() =>
          f.first.oauth.beginAuthorization({
            audience: f.metadata.audience,
            scopes: ['openid', 'orders.read'],
            returnPath: '/orders',
          }),
        ),
        callback = await f.authorize(start.authorizationUrl);
      await assert.rejects(f.first.oauth.exchangeCode(callback));
      await assert.rejects(foreign.run(() => f.second.oauth.exchangeCode(callback)));
      const grant = await account.run(() => f.first.oauth.exchangeCode(callback));
      await assert.rejects(foreign.run(() => f.second.oauth.refresh(grant.refreshRef!)));
      const outcomes = await account.run(() =>
        Promise.allSettled([
          f.first.oauth.refresh(grant.refreshRef!),
          f.second.oauth.refresh(grant.refreshRef!),
        ]),
      );
      assert.ok(outcomes.filter((result) => result.status === 'fulfilled').length <= 1);
      const winner = outcomes.find((result) => result.status === 'fulfilled');
      await assert.rejects(account.run(() => f.second.oauth.refresh(grant.refreshRef!)));
      if (winner?.status === 'fulfilled')
        await assert.rejects(account.run(() => f.first.oauth.refresh(winner.value.refreshRef!)));
    } finally {
      await f.close();
    }
  },
);
test(
  'OAuth current primary revocation, external-key outage and real PostgreSQL outage fail closed',
  { timeout: 30000 },
  async () => {
    const f = await oauthFixture();
    try {
      const account = await f.session(),
        start = await account.run(() =>
          f.first.oauth.beginAuthorization({
            audience: f.metadata.audience,
            scopes: ['openid', 'orders.read'],
            returnPath: '/orders',
          }),
        ),
        grant = await account.run(async () =>
          f.second.oauth.exchangeCode(await f.authorize(start.authorizationUrl)),
        );
      f.state.secretsAvailable = false;
      await assert.rejects(account.run(() => f.first.oauth.refresh(grant.refreshRef!)));
      f.state.secretsAvailable = true;
      await f.primary.revokePrimary(account.subject, String(account.identity.claims.sid));
      await assert.rejects(account.run(() => f.first.oauth.refresh(grant.refreshRef!)));
      const current = await f.session({ sid: 'oauth-live-session' });
      await f.backend.app.sql.execute('main', {
        text: `DROP TABLE ${f.backend.schema}.security_records`,
      });
      await assert.rejects(
        current.run(() => f.first.oauth.clientCredentials(f.metadata.audience, ['orders.read'])),
      );
    } finally {
      await f.close();
    }
  },
);
