// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { httpSecurityFixture } from '../../../examples/postgres/dist-test/integration/http-security-fixture.js';
import { createHttpTlsFixture } from '../http-tls.mjs';
import {
  countedCsrfSettings,
  csrfCookieName,
  csrfExchange,
  frameworkCsrf,
  nativeCsrf,
} from '../csrf-workload.mjs';

const emptyCounts = Object.freeze({
    sessionResolve: 0,
    authorityRequire: 0,
    nativeKeyDigest: 0,
    ownerDigest: 0,
    stateDigest: 0,
    storeRead: 0,
    storeCompareAndSet: 0,
  }),
  verificationCounts = Object.freeze({
    sessionResolve: 1,
    authorityRequire: 1,
    nativeKeyDigest: 1,
    ownerDigest: 1,
    stateDigest: 1,
    storeRead: 1,
    storeCompareAndSet: 0,
  });

test(
  'Native CSRF and framework HTTPS use the same real OIDC session, HMAC and durable state before protected effects',
  { timeout: 60000 },
  async () => {
    assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
    const fixture = await httpSecurityFixture();
    let tls, framework, native;
    try {
      tls = await createHttpTlsFixture();
      const countedFramework = countedCsrfSettings(fixture.settings),
        countedNative = countedCsrfSettings(fixture.settings);
      framework = await frameworkCsrf(countedFramework.settings, tls);
      native = await nativeCsrf(countedNative.settings, tls);
      const account = await fixture.session(),
        foreign = await fixture.session({ tenant_id: 'tenant-b', sid: 'csrf-comparison-foreign' });
      countedFramework.reset();
      const issued = await csrfExchange(
        framework,
        tls,
        {
          cookie: '__Host-session=' + account.issued.value,
          'x-session-hint': account.issued.sessionId,
        },
        '/token',
      );
      assert.equal(issued.status, 200);
      assert.equal(issued.tls.authorized, true);
      assert.equal(issued.tls.protocol, 'TLSv1.3');
      const token = JSON.parse(issued.body).token;
      assert.equal(typeof token, 'string');
      assert.ok(/^v1\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]+$/.test(token));
      const cookies = issued.headers['set-cookie'];
      assert.ok(Array.isArray(cookies) && cookies.length === 1);
      const cookie = cookies[0];
      for (const attribute of ['Secure', 'HttpOnly', 'SameSite=Strict', 'Path=/'])
        assert.ok(cookie.includes(attribute));
      assert.ok(cookie.startsWith(csrfCookieName + '='));
      assert.deepEqual(countedFramework.snapshot(), {
        ...emptyCounts,
        authorityRequire: 1,
        nativeKeyDigest: 1,
        ownerDigest: 1,
        stateDigest: 1,
        storeCompareAndSet: 1,
      });
      const durable = await fixture.backend.app.sql.query('main', {
        text: `SELECT id,body FROM ${fixture.backend.schema}.security_records WHERE namespace=:namespace`,
        bindings: { namespace: 'arkenivajs.security-http.csrf.v1' },
      });
      assert.equal(durable.rows.length, 1);
      const encoded = JSON.stringify(durable.rows);
      for (const secret of [
        token,
        token.split('.')[1],
        account.issued.value,
        account.issued.sessionId,
        account.token,
      ])
        assert.equal(encoded.includes(secret), false);

      const headers = {
        cookie: '__Host-session=' + account.issued.value + '; ' + cookie.split(';')[0],
        origin: 'https://app.fixture.invalid',
        'x-csrf-token': token,
      };
      for (const [server, counters] of [
        [native, countedNative],
        [framework, countedFramework],
      ]) {
        counters.reset();
        const before = server.effects(),
          accepted = await csrfExchange(server, tls, headers);
        assert.equal(accepted.status, 200);
        assert.equal(server.effects(), before + 1);
        assert.deepEqual(counters.snapshot(), verificationCounts);
        assert.equal(accepted.headers['x-content-type-options'], 'nosniff');
        assert.equal(accepted.headers['referrer-policy'], 'no-referrer');
        for (const candidate of [
          { ...headers, 'x-csrf-token': '' },
          { ...headers, cookie: '__Host-session=' + account.issued.value },
          { ...headers, origin: 'https://foreign.fixture.invalid' },
          { ...headers, origin: 'https://app.fixture.invalid.evil.invalid' },
        ]) {
          counters.reset();
          const denied = await csrfExchange(server, tls, candidate);
          assert.equal(denied.status, 403);
          assert.equal(server.effects(), before + 1);
          assert.deepEqual(counters.snapshot(), emptyCounts);
        }
        counters.reset();
        const invalid = await csrfExchange(server, tls, {
          ...headers,
          'x-csrf-token': token + 'x',
        });
        assert.equal(invalid.status, 403);
        assert.equal(server.effects(), before + 1);
        assert.deepEqual(counters.snapshot(), verificationCounts);

        counters.reset();
        const deniedTenant = await csrfExchange(server, tls, {
          ...headers,
          cookie: '__Host-session=' + foreign.issued.value + '; ' + cookie.split(';')[0],
        });
        assert.equal(deniedTenant.status, 403);
        assert.equal(server.effects(), before + 1);
        assert.deepEqual(counters.snapshot(), verificationCounts);

        counters.reset();
        const recovered = await csrfExchange(server, tls, headers);
        assert.equal(recovered.status, 200);
        assert.equal(server.effects(), before + 2);
        assert.deepEqual(counters.snapshot(), verificationCounts);
      }

      await fixture.primary.revokePrimary(account.subject, String(account.identity.claims.sid));
      for (const [server, counters] of [
        [native, countedNative],
        [framework, countedFramework],
      ]) {
        counters.reset();
        const before = server.effects(),
          denied = await csrfExchange(server, tls, headers);
        assert.equal(denied.status, 403);
        assert.equal(server.effects(), before);
        assert.deepEqual(counters.snapshot(), { ...emptyCounts, sessionResolve: 1 });
      }
    } finally {
      try {
        await native?.close();
      } finally {
        try {
          await framework?.close();
        } finally {
          try {
            await tls?.close();
          } finally {
            await fixture.close();
          }
        }
      }
    }
  },
);
