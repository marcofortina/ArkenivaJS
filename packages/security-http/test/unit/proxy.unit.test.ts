// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createApi } from '@arkenivajs/api';
import { fixtureSettings } from './fixture.js';
import { capture } from '../../dist/settings.js';
import { createNative } from '../../dist/native.js';
import { providerTask } from '../../dist/provider-task.js';

test('Actual plaintext proxy traffic is secure only for a configured peer and exactly one HTTPS protocol value', async () => {
  for (const [cidrs, protocol, expected] of [
    [[], 'https', 403],
    [['127.0.0.1/32'], 'https', 200],
    [['127.0.0.1/32'], 'http', 403],
    [['127.0.0.1/32'], 'https,http', 403],
    [['127.0.0.2/32'], 'https', 403],
  ] as const) {
    const f = fixtureSettings(),
      settings = capture({ ...f.settings, cookieRoutes: [], trustedProxyCidrs: cidrs });
    const owner = new AbortController(),
      key = providerTask(settings, owner.signal);
    const api = createApi({
      service: { name: 'proxy-security-native', version: '1.0.0', environment: 'test' },
      host: '127.0.0.1',
      port: 0,
    });
    let ready = false;
    const managed = await createNative(
      settings,
      api.native(),
      owner.signal,
      () => ready,
      false,
      key,
    );
    api.get('/token', {
      schema: {
        response: {
          type: 'object',
          properties: { token: { type: 'string' } },
          required: ['token'],
          additionalProperties: false,
        },
      },
      auth: { required: false },
      async handler() {
        return { token: await managed.service.csrfToken({ sessionId: f.alice.sessionId }) };
      },
    });
    try {
      await api.start();
      ready = true;
      const response = await fetch(api.address()! + '/token', {
        headers: { cookie: '__Host-session=' + f.alice.cookie, 'x-forwarded-proto': protocol },
      });
      assert.equal(response.status, expected);
      assert.equal(response.headers.get('strict-transport-security'), 'max-age=31536000');
      await response.arrayBuffer();
      if (expected === 403) assert.equal(f.state.authorizations, 0);
    } finally {
      ready = false;
      try {
        await managed.close();
      } finally {
        try {
          await api.close();
        } finally {
          owner.abort();
          await key.close();
        }
      }
    }
  }
});
