// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { httpSecurityFixture } from './http-security-fixture.js';

test(
  'CSRF with actual OIDC and durable sessions verifies on independent PostgreSQL pools and survives HTTP application restart',
  { timeout: 30000 },
  async () => {
    const f = await httpSecurityFixture();
    try {
      const account = await f.session();
      const response = await fetch(f.first.origin + '/token', {
        headers: {
          cookie: '__Host-session=' + account.issued.value,
          'x-session-hint': account.issued.sessionId,
        },
      });
      assert.equal(response.status, 200);
      const { token } = (await response.json()) as { token: string },
        seed = response.headers.get('set-cookie')!.split(';')[0]!;
      const headers = {
        cookie: '__Host-session=' + account.issued.value + '; ' + seed,
        origin: 'https://app.fixture.invalid',
        'x-csrf-token': token,
      };
      for (const origin of [f.first.origin, f.second.origin]) {
        const accepted = await fetch(origin + '/protected', { method: 'POST', headers });
        assert.equal(accepted.status, 200);
        await accepted.arrayBuffer();
      }
      const rows = await f.backend.app.sql.query<{ id: string; body: string }>('main', {
        text: `SELECT id,body FROM ${f.backend.schema}.security_records WHERE namespace='arkenivajs.security-http.csrf.v1'`,
      });
      assert.equal(rows.rows.length, 1);
      const stored = JSON.stringify(rows.rows);
      for (const secret of [
        token,
        token.split('.')[1]!,
        account.issued.value,
        account.issued.sessionId,
        account.token,
      ])
        assert.equal(stored.includes(secret), false);
      await f.first.app.stop();
      const restarted = await f.instance(),
        accepted = await fetch(restarted.origin + '/protected', { method: 'POST', headers });
      assert.equal(accepted.status, 200);
      await accepted.arrayBuffer();
      assert.equal(f.state.effects, 3);
    } finally {
      await f.close();
    }
  },
);

test(
  'CSRF actual session revocation, foreign tenants and forged session identifiers never authorize a protected operation',
  { timeout: 30000 },
  async () => {
    const f = await httpSecurityFixture();
    try {
      const a = await f.session(),
        b = await f.session({ tenant_id: 'tenant-b', sid: 'csrf-other-session' });
      await assert.rejects(f.first.service.csrfToken({ sessionId: a.issued.sessionId }));
      await assert.rejects(
        b.run(() => f.first.service.csrfToken({ sessionId: a.issued.sessionId })),
      );
      const token = await a.run(() => f.first.service.csrfToken({ sessionId: a.issued.sessionId }));
      await assert.rejects(
        b.run(() =>
          f.second.service.verifyCsrf(
            { sessionId: b.issued.sessionId, origin: 'https://app.fixture.invalid' },
            token,
          ),
        ),
      );
      await a.run(() =>
        f.second.service.verifyCsrf(
          { sessionId: a.issued.sessionId, origin: 'https://app.fixture.invalid' },
          token,
        ),
      );
      await f.primary.revokePrimary(a.subject, String(a.identity.claims.sid));
      await assert.rejects(
        a.run(() =>
          f.second.service.verifyCsrf(
            { sessionId: a.issued.sessionId, origin: 'https://app.fixture.invalid' },
            token,
          ),
        ),
      );
      assert.equal(f.state.effects, 0);
    } finally {
      await f.close();
    }
  },
);

test(
  'CSRF real PostgreSQL outage and external-key outage reject issuance/verification without per-pod fallback',
  { timeout: 30000 },
  async () => {
    const f = await httpSecurityFixture();
    try {
      const a = await f.session(),
        context = { sessionId: a.issued.sessionId, origin: 'https://app.fixture.invalid' };
      const token = await a.run(() => f.first.service.csrfToken({ sessionId: a.issued.sessionId }));
      f.state.secretAvailable = false;
      await assert.rejects(a.run(() => f.second.service.verifyCsrf(context, token)));
      f.state.secretAvailable = true;
      await f.backend.app.sql.execute('main', {
        text: `DROP TABLE ${f.backend.schema}.security_records`,
      });
      await assert.rejects(a.run(() => f.second.service.verifyCsrf(context, token)));
      await assert.rejects(
        a.run(() => f.first.service.csrfToken({ sessionId: a.issued.sessionId })),
      );
      assert.equal(f.state.effects, 0);
    } finally {
      await f.close();
    }
  },
);
