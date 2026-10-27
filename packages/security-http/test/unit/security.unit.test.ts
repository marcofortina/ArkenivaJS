// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { fixtureSettings, startFixture } from './fixture.js';
import { securityHttpPlugin } from '../../dist/index.js';
import { headerPolicy } from '../../dist/headers.js';
import { installNativeHeaders } from '../../dist/headers.js';
import { createApi } from '@arkenivajs/api';

const denied = (error: unknown) => error instanceof KitError;

test('Readiness rejection before native reply decoration still receives the complete hardening policy', async () => {
  let ready = true;
  const api = createApi({
    service: { name: 'header-readiness', version: '1.0.0', environment: 'test' },
    host: '127.0.0.1',
    port: 0,
    isReady: () => ready,
  });
  const policy = headerPolicy(fixtureSettings().settings.policy);
  installNativeHeaders(api.native(), () => policy);
  api.get('/owned', {
    schema: { response: { type: 'object', additionalProperties: false } },
    auth: { required: false },
    handler: () => ({}),
  });
  try {
    await api.start();
    ready = false;
    const response = await fetch(api.address()! + '/owned');
    assert.equal(response.status, 503);
    assert.equal(response.headers.get('strict-transport-security'), 'max-age=31536000');
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
    assert.match(response.headers.get('content-security-policy')!, /default-src 'self'/);
    await response.arrayBuffer();
  } finally {
    await api.close();
  }
});

test('A browser reuses its live session-bound nonce so repeated token issuance preserves other tabs and bounded state', async () => {
  const f = await startFixture();
  try {
    const first = await fetch(f.origin + '/token', {
      headers: { cookie: '__Host-session=' + f.alice.cookie, 'x-session-hint': f.alice.sessionId },
    });
    const one = (await first.json()) as { token: string },
      cookie = first.headers.get('set-cookie')!.split(';')[0]!;
    const browser = '__Host-session=' + f.alice.cookie + '; ' + cookie;
    const second = await fetch(f.origin + '/token', {
      headers: { cookie: browser, 'x-session-hint': f.alice.sessionId },
    });
    assert.equal(second.status, 200);
    const two = (await second.json()) as { token: string };
    assert.equal(one.token.split('.')[1], two.token.split('.')[1]);
    assert.equal(f.rows.size, 1);
    assert.equal(f.state.writes, 1);
    for (const token of [one.token, two.token]) {
      const response = await fetch(f.origin + '/protected', {
        method: 'POST',
        headers: { cookie: browser, origin: 'https://app.fixture.invalid', 'x-csrf-token': token },
      });
      assert.equal(response.status, 200);
      await response.arrayBuffer();
    }
  } finally {
    await f.close();
  }
});

test('Native Helmet installs CSP, HSTS, nosniff and no-referrer on actual responses and trusted policy updates', async () => {
  const f = await startFixture();
  try {
    const first = await fetch(f.origin + '/ordinary', { method: 'POST' });
    assert.equal(first.status, 200);
    assert.match(first.headers.get('content-security-policy')!, /default-src 'self'/);
    assert.match(first.headers.get('content-security-policy')!, /frame-ancestors 'none'/);
    assert.equal(first.headers.get('strict-transport-security'), 'max-age=31536000');
    assert.equal(first.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(first.headers.get('referrer-policy'), 'no-referrer');
    await first.arrayBuffer();
    const policy = f.service.getEffectivePolicy();
    assert.ok(Object.isFrozen(policy.contentSecurityPolicy));
    f.service.installHeaders({ ...policy, frameAncestors: ["'self'"], hstsMaxAgeSeconds: 1234 });
    const second = await fetch(f.origin + '/not-present');
    assert.equal(second.status, 404);
    assert.match(second.headers.get('content-security-policy')!, /frame-ancestors 'self'/);
    assert.equal(second.headers.get('strict-transport-security'), 'max-age=1234');
    await second.arrayBuffer();
  } finally {
    await f.close();
  }
});

test('Authorized CSRF tokens are session and tenant bound, reusable within expiry and never persisted as plaintext', async () => {
  const f = await startFixture();
  try {
    await assert.rejects(f.service.csrfToken({ sessionId: f.alice.sessionId }), denied);
    const token = await f.as(f.alice.cookie, () =>
      f.service.csrfToken({ sessionId: f.alice.sessionId }),
    );
    const context = { sessionId: f.alice.sessionId, origin: 'https://app.fixture.invalid' };
    await f.as(f.alice.cookie, () => f.service.verifyCsrf(context, token));
    await f.as(f.alice.cookie, () => f.service.verifyCsrf(context, token));
    await assert.rejects(
      f.as(f.bob.cookie, () =>
        f.service.verifyCsrf({ ...context, sessionId: f.bob.sessionId }, token),
      ),
      denied,
    );
    await assert.rejects(
      f.as(f.alice.cookie, () => f.service.csrfToken({ sessionId: f.bob.sessionId })),
      denied,
    );
    const persisted = JSON.stringify([...f.rows]);
    for (const secret of [
      token,
      token.split('.')[1]!,
      f.alice.sessionId,
      f.alice.cookie,
      f.bob.cookie,
    ])
      assert.equal(persisted.includes(secret), false);
    f.credentials.delete(f.alice.cookie);
    await assert.rejects(
      f.as(f.alice.cookie, () => f.service.verifyCsrf(context, token)),
      denied,
    );
  } finally {
    await f.close();
  }
});

test('The real cookie route invokes native Fastify CSRF verification only after trusted session and exact origin checks', async () => {
  const f = await startFixture();
  try {
    const issued = await fetch(f.origin + '/token', {
      headers: { cookie: '__Host-session=' + f.alice.cookie, 'x-session-hint': f.alice.sessionId },
    });
    assert.equal(issued.status, 200);
    const { token } = (await issued.json()) as { token: string };
    const csrfCookie = issued.headers.get('set-cookie')!;
    assert.match(csrfCookie, /Secure/);
    assert.match(csrfCookie, /HttpOnly/);
    assert.match(csrfCookie, /SameSite=Strict/);
    assert.match(csrfCookie, /Path=\//);
    const headers = {
      cookie: '__Host-session=' + f.alice.cookie + '; ' + csrfCookie.split(';')[0],
      origin: 'https://app.fixture.invalid',
      'x-csrf-token': token,
    };
    const accepted = await fetch(f.origin + '/protected', { method: 'POST', headers });
    assert.equal(accepted.status, 200);
    await accepted.arrayBuffer();
    for (const altered of [
      { ...headers, origin: 'https://evil.fixture.invalid' },
      { ...headers, origin: 'https://app.fixture.invalid.attacker.invalid' },
      { ...headers, origin: 'null' },
      { ...headers, 'x-csrf-token': token + 'x' },
      { ...headers, 'x-csrf-token': '' },
      { ...headers, cookie: '__Host-session=' + f.alice.cookie },
      { ...headers, cookie: '__Host-session=' + f.bob.cookie + '; ' + csrfCookie.split(';')[0] },
    ]) {
      const response = await fetch(f.origin + '/protected', { method: 'POST', headers: altered });
      assert.equal(response.status, 403);
      await response.arrayBuffer();
    }
    assert.equal(f.state.effects, 1);
    const native = f.app.api.native() as { csrfProtection: (...args: unknown[]) => void };
    assert.equal(typeof native.csrfProtection, 'function');
    const log = f.logs.join('');
    assert.equal(log.includes(token), false);
    assert.equal(log.includes(f.alice.cookie), false);
  } finally {
    await f.close();
  }
});

test('Header policy and factory reject injection, unknown properties, missing origins and unsafe CSRF route settings', () => {
  const f = fixtureSettings(),
    base = f.settings.policy;
  for (const policy of [
    { ...base, hstsMaxAgeSeconds: 0 },
    { ...base, hstsMaxAgeSeconds: 1.5 },
    { ...base, frameAncestors: ['*'] },
    { ...base, contentSecurityPolicy: { 'default-src': ['*'] } },
    { ...base, contentSecurityPolicy: { 'default-src': ["'self'\r\nx-evil: yes"] } },
    { ...base, contentSecurityPolicy: { 'default-src': ["'self'; script-src *"] } },
    { ...base, unknown: true },
  ])
    assert.throws(() => headerPolicy(policy), denied);
  for (const input of [
    { ...f.settings, allowedOrigins: [] },
    { ...f.settings, allowedOrigins: null },
    { ...f.settings, cookieSession: undefined },
    { ...f.settings, cookieRoutes: null },
    { ...f.settings, policy: { ...base, csrfEnabled: false } },
    { ...f.settings, cookieRoutes: [{ method: 'GET', path: '/protected' }] },
    { ...f.settings, csrfHmac: { algorithm: 'sha1' } },
    { ...f.settings, unknown: true },
  ])
    assert.throws(() => securityHttpPlugin(input as never), denied);
});
