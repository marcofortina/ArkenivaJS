// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { magicLinksPlugin, MAGICLINK_CAPABILITY } from '@arkenivajs/security-magiclink';
import type { MagicLinkService } from '@arkenivajs/security-magiclink';
import { nativeFixtureHmac, memoryFixtureStore } from '../magiclink-unit-fixture.js';

test('Installed public magic-link artifacts preserve explicit confirmation and one-use semantics', async () => {
  const key = randomBytes(32),
    owner = Object.freeze({ issuer: 'https://identity.fixture.invalid', subject: 'unit-account' });
  let authenticated = true;
  const app = await createApplication({
    service: { name: 'magiclink-public-consumer', version: '1.0.0', environment: 'test' },
    logging: { level: 'silent' },
    plugins: [
      loggingPlugin(),
      magicLinksPlugin({
        stateStore: {
          store: memoryFixtureStore(),
          securityLevel: 'test-only',
          operationTimeoutMs: 1000,
        },
        hmac: nativeFixtureHmac(key),
        signingKeyRef: 'fixture/magiclink',
        trustedBaseUrl: 'https://identity.fixture.invalid/confirm',
        ttlMs: 60000,
        maxClaimsPerHour: 4,
        authority: {
          async require(action, hint) {
            if (
              (!action.startsWith('magiclink.consume.') && !authenticated) ||
              (hint &&
                (hint.issuer !== owner.issuer || hint.subject !== owner.subject || hint.tenant))
            )
              throw new Error('Independent unit policy denied the operation');
            return owner;
          },
        },
      }),
    ],
  });
  try {
    await app.start();
    const magic = app.resolve<MagicLinkService>(MAGICLINK_CAPABILITY);
    const issued = await magic.issue(owner, 'email-verify');
    authenticated = false;
    await assert.rejects(magic.issue(owner, 'login'), { code: 'EK_MAGICLINK_INVALID' });
    const url = new URL(issued.redemptionUrl);
    assert.equal(url.search, '');
    assert.equal(new URLSearchParams(url.hash.slice(1)).get('purpose'), 'email-verify');
    await assert.rejects(
      magic.consume(issued.value, { method: 'GET' as 'POST', purpose: 'email-verify' }),
    );
    const outcomes = await Promise.allSettled([
      magic.consume(issued.value, { method: 'POST', purpose: 'email-verify' }),
      magic.consume(issued.value, { method: 'POST', purpose: 'email-verify' }),
    ]);
    assert.equal(outcomes.filter((result) => result.status === 'fulfilled').length, 1);
    await assert.rejects(magic.consume(issued.value, { method: 'POST', purpose: 'email-verify' }), {
      code: 'EK_MAGICLINK_REPLAY',
    });
  } finally {
    await app.stop();
    key.fill(0);
  }
});
