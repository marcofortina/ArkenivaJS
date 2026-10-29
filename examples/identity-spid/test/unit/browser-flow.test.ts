// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import type { SpidService } from '@arkenivajs/identity-spid';
import {
  browserRedirect,
  verifyBrowserCallback,
  consumeBrowserLogin,
} from '../../dist/browser-flow.js';

test('Browser redirects set bounded first-party cookies and prevent sensitive caching or referrers', () => {
  const state = randomBytes(32).toString('hex'),
    transfer = browserRedirect({
      transactionId: state,
      redirectUrl: 'https://provider.example.test/authorize?request=opaque',
      expiresAt: new Date(Date.now() + 600000).toISOString(),
    });
  assert.equal(transfer.status, 303);
  assert.equal(
    transfer.headers['set-cookie'],
    '__Host-spid-flow=' + state + '; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300',
  );
  assert.equal(transfer.headers['cache-control'], 'no-store');
  assert.equal(transfer.headers['referrer-policy'], 'no-referrer');
  for (const change of [
    { transactionId: 'invalid' },
    { transactionId: state + '\n' },
    { redirectUrl: 'http://provider.example.test/authorize' },
    { redirectUrl: 'https://user:password@provider.example.test/authorize' },
    { redirectUrl: 'https://provider.example.test/authorize\r\nInjected: value' },
    { expiresAt: 'invalid' },
    { expiresAt: new Date(Date.now() - 1000).toISOString() },
  ])
    assert.throws(() =>
      browserRedirect({
        transactionId: state,
        redirectUrl: 'https://provider.example.test/authorize',
        expiresAt: new Date(Date.now() + 60000).toISOString(),
        ...change,
      }),
    );
});

test('Missing, foreign, duplicate or malformed browser state is rejected before the service can run', async () => {
  const state = randomBytes(32).toString('hex'),
    cookie = '__Host-spid-flow=' + state,
    configured = 'https://application.example.test/callback?registration=fixed',
    response = configured + '&code=opaque&iss=https%3A%2F%2Fprovider.example.test&state=' + state;
  assert.equal(verifyBrowserCallback('other=value; ' + cookie, response, configured), response);
  let calls = 0;
  const unavailable = async (): Promise<never> => {
    calls++;
    throw new Error('The native service must not run');
  };
  const service: SpidService = {
    forProfile() {
      return service;
    },
    beginAuthentication: unavailable,
    consumeAuthentication: unavailable,
    metadata: unavailable,
    verifyFederationTrust: unavailable,
  };
  for (const [cookies, target] of [
    [undefined, response],
    ['', response],
    ['__Host-spid-flow=' + 'f'.repeat(64), response],
    [cookie + '; ' + cookie, response],
    ['__Host-spid-flow=not-a-reference', response],
    [cookie, response + '&state=' + state],
    [cookie, response.replace('&state=' + state, '')],
    [cookie, response.replace('application.example.test', 'foreign.example.test')],
    [cookie, response.replace('/callback', '/foreign')],
    [cookie, response.replace('registration=fixed', 'registration=foreign')],
    [cookie, response + '&registration=fixed'],
    [cookie, response + '#fragment'],
    ['x'.repeat(8193), response],
    [cookie, 'x'.repeat(65537)],
  ] as const)
    await assert.rejects(() => consumeBrowserLogin(service, cookies, target, configured), {
      message: 'The browser authentication transaction is unavailable',
    });
  assert.equal(calls, 0);
});
