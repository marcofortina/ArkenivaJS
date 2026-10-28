// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WSSecurity } from 'soap';
import { verifySecurityHeader } from '../../dist/security-header.js';
import { response } from '../fixture.js';

test('Native UsernameToken proof must appear exactly once inside the SOAP Header and remain unchanged', () => {
  const native = new WSSecurity('fixture-user', 'sample', {
      passwordType: 'PasswordDigest',
      hasNonce: true,
      hasTimeStamp: true,
      hasTokenCreated: true,
    }),
    token = native.toXML();
  const wire = response.replace('<s:Body>', '<s:Header>' + token + '</s:Header><s:Body>');
  assert.doesNotThrow(() => verifySecurityHeader(wire, token));
  for (const source of [
    response,
    wire.replace('fixture-user', 'different-user'),
    wire.replace('</s:Header>', token + '</s:Header>'),
    response.replace('<s:Body>', '<s:Body>' + token),
  ])
    assert.throws(() => verifySecurityHeader(source, token));
  assert.throws(() => verifySecurityHeader(wire, undefined));
  assert.notEqual(native.toXML(), token);
});
