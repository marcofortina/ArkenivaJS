// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { samlBrowserRedirect, verifySamlBrowserCallback } from '../../dist/saml-browser-flow.js';

test('SAML browser transfer uses a separate bounded Secure host cookie for cross-site POST', () => {
  const state = randomBytes(32).toString('hex'),
    login = {
      transactionId: state,
      redirectUrl: 'https://idp.example.test/login',
      expiresAt: new Date(Date.now() + 600000).toISOString(),
    },
    transfer = samlBrowserRedirect(login);
  assert.equal(transfer.status, 303);
  assert.equal(
    transfer.headers['set-cookie'],
    `__Host-spid-saml-flow=${state}; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=300`,
  );
  assert.equal(transfer.headers['cache-control'], 'no-store');
  for (const change of [
    { transactionId: state + '\n' },
    { transactionId: 'invalid' },
    { expiresAt: 'invalid' },
    { expiresAt: new Date(Date.now() - 1).toISOString() },
    { redirectUrl: 'http://idp.example.test' },
    { redirectUrl: 'https://user:password@idp.example.test' },
    { redirectUrl: 'https://idp.example.test/#fragment' },
  ])
    assert.throws(() => samlBrowserRedirect({ ...login, ...change }));
});

test('POST ACS rejects missing or duplicate cookies, body transaction overrides, malformed forms and executable inputs', () => {
  const transactionId = randomBytes(32).toString('hex'),
    relayState = '_' + randomBytes(20).toString('hex'),
    samlResponse = Buffer.from('<signed-fixture/>').toString('base64'),
    issuer = 'https://idp.example.test',
    acs = 'https://application.example.test/acs?fixed=registration',
    cookie = '__Host-spid-saml-flow=' + transactionId,
    request = {
      method: 'POST',
      url: acs,
      contentType: 'application/x-www-form-urlencoded',
      body: new URLSearchParams({ SAMLResponse: samlResponse, RelayState: relayState }).toString(),
    };
  assert.deepEqual(verifySamlBrowserCallback(cookie, request, acs, issuer), {
    transactionId,
    issuer,
    relayState,
    samlResponse,
  });
  for (const invalid of [
    undefined,
    '',
    '__Host-spid-flow=' + transactionId,
    cookie + '; ' + cookie,
    cookie + '\n',
    cookie.replace(transactionId, 'invalid'),
    'x'.repeat(8193),
  ])
    assert.throws(() => verifySamlBrowserCallback(invalid, request, acs, issuer));
  let hooks = 0;
  for (const invalid of [
    { ...request, method: 'GET' },
    { ...request, url: acs + '&extra=1' },
    { ...request, url: 'https://foreign.example.test/acs' },
    { ...request, contentType: 'application/json' },
    { ...request, contentType: undefined },
    { ...request, body: 'x'.repeat(65537) },
    { ...request, body: request.body + '&transactionId=' + transactionId },
    { ...request, body: request.body + '&RelayState=' + relayState },
    { ...request, body: request.body + '&SAMLResponse=' + samlResponse },
    { ...request, body: request.body.replace('SAMLResponse=', 'unknown=') },
    { ...request, body: 'SAMLResponse=%FF&RelayState=' + relayState },
    { ...request, body: 'SAMLResponse=%GG&RelayState=' + relayState },
    {
      ...request,
      body: new URLSearchParams({
        SAMLResponse: samlResponse,
        RelayState: relayState + '\n',
      }).toString(),
    },
    Object.defineProperty({ ...request }, 'body', {
      enumerable: true,
      get() {
        hooks++;
        return request.body;
      },
    }),
    new Proxy(request, {
      get() {
        hooks++;
        throw new Error('Executable request');
      },
    }),
  ])
    assert.throws(() => verifySamlBrowserCallback(cookie, invalid, acs, issuer));
  assert.equal(hooks, 0);
});
