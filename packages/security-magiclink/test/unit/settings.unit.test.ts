// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { magicLinksPlugin } from '../../dist/index.js';
import type { MagicLinksPluginSettings } from '../../dist/index.js';
import { fixture, application } from '../fixture.js';

test('Configuration rejects unsafe origins, numeric coercion and incomplete provider ports before I/O', () => {
  const source = fixture(),
    checks = source.state.hmacChecks;
  const invalid: unknown[] = [
    ...[
      'http://example.test',
      'https://user:password@example.test',
      'https://example.test/?token=x',
      'https://example.test/#token=x',
    ].map((trustedBaseUrl) => ({ ...source.settings, trustedBaseUrl })),
    ...[0, -1, 0.5, Infinity, NaN, 900001, '1000'].map((ttlMs) => ({ ...source.settings, ttlMs })),
    ...[0, 1.5, 100001, '1'].map((maxClaimsPerHour) => ({ ...source.settings, maxClaimsPerHour })),
    { ...source.settings, signingKeyRef: '' },
    { ...source.settings, authority: {} },
    { ...source.settings, hmac: { ...source.settings.hmac, algorithm: 'SHA256' } },
    { ...source.settings, stateStore: { ...source.settings.stateStore, operationTimeoutMs: 0 } },
    { ...source.settings, stateStore: { ...source.settings.stateStore, store: { read() {} } } },
    { ...source.settings, environment: 'test' },
  ];
  for (const settings of invalid)
    assert.throws(() => magicLinksPlugin(settings as MagicLinksPluginSettings), {
      code: 'EK_CONFIG_INVALID',
    });
  let accessed = 0;
  const accessor = { ...source.settings };
  Object.defineProperty(accessor, 'authority', {
    get() {
      accessed++;
      throw new Error('Unexpected getter');
    },
  });
  assert.throws(() => magicLinksPlugin(accessor), { code: 'EK_CONFIG_INVALID' });
  assert.throws(
    () =>
      magicLinksPlugin(
        new Proxy(source.settings, {
          get() {
            accessed++;
          },
        }),
      ),
    { code: 'EK_CONFIG_INVALID' },
  );
  assert.equal(accessed, 0);
  assert.equal(source.state.hmacChecks, checks);
});

test('A permissive HMAC verifier fails startup rather than trusting arbitrary proofs', async () => {
  const source = fixture();
  await assert.rejects(
    application({
      ...source.settings,
      hmac: {
        ...source.settings.hmac,
        async verify() {
          return true;
        },
      },
    }),
  );
});

test('Only a valid token can request current authority resolution; missing records and altered proofs cannot', async () => {
  const source = fixture();
  let authorityCalls = 0;
  const { app, magic } = await application({
    ...source.settings,
    authority: {
      async require(...args) {
        authorityCalls++;
        return source.settings.authority.require(...args);
      },
    },
  });
  try {
    const issued = await magic.issue(source.owner, 'login');
    const before = authorityCalls;
    const secretStart = issued.value.lastIndexOf('.') + 1;
    const altered =
      issued.value.slice(0, secretStart) +
      (issued.value[secretStart] === 'A' ? 'B' : 'A') +
      issued.value.slice(secretStart + 1);
    await assert.rejects(magic.consume(altered, { method: 'POST', purpose: 'login' }), {
      code: 'EK_MAGICLINK_INVALID',
    });
    const absent =
      issued.value.slice(0, 4) + '00000000-0000-4000-8000-000000000000' + issued.value.slice(40);
    await assert.rejects(magic.consume(absent, { method: 'POST', purpose: 'login' }), {
      code: 'EK_MAGICLINK_INVALID',
    });
    assert.equal(authorityCalls, before);
    await magic.consume(issued.value, { method: 'POST', purpose: 'login' });
    assert.equal(authorityCalls, before + 1);
  } finally {
    await app.stop();
  }
});
