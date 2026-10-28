// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DOMParser } from '@xmldom/xmldom';
import { browserTransfer } from '../../dist/browser-transfer.js';

test('POST transfer escapes every HTML attribute and restricts the form destination without inline scripts', () => {
  const marker = `"><script>private-marker</script>&' escaped`;
  const response = browserTransfer({
    binding: 'post',
    requestId: '_owned',
    expiresAt: new Date().toISOString(),
    actionUrl: 'https://idp.fixture.invalid/login',
    fields: { SAMLRequest: 'owned-base64', RelayState: marker },
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(response.headers['referrer-policy'], 'no-referrer');
  assert.equal(
    response.headers['content-security-policy'],
    "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action https://idp.fixture.invalid",
  );
  assert.ok(!response.body.includes('<script>'));
  const document = new DOMParser().parseFromString(
    response.body.slice('<!doctype html>'.length),
    'text/xml',
  );
  assert.equal(document.getElementsByTagName('input')[1]!.getAttribute('value'), marker);
  assert.throws(() =>
    browserTransfer({
      binding: 'post',
      requestId: '_owned',
      expiresAt: new Date().toISOString(),
      actionUrl: 'http://foreign.invalid/login',
      fields: { SAMLRequest: 'owned-base64' },
    }),
  );
});
