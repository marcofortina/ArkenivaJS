// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import { createApplication } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { loggingPlugin } from '@arkenivajs/logging';
import { scimPlugin } from '../../dist/index.js';
import type { ScimPluginSettings } from '../../dist/index.js';
import { fixture } from '../fixture.js';

test('Malformed SCIM plugin configuration and executable accessors fail before listener or provider work', async () => {
  const f = await fixture();
  const settings: ScimPluginSettings = {
    users: f.provider('Users'),
    groups: f.provider('Groups'),
    authority: f.authority,
    maxPageSize: 100,
    maxFilterDepth: 8,
    maxRequestBytes: 262144,
    maxConcurrent: 8,
    capabilities: { patch: true, bulk: false, filter: true, etag: true, sort: true },
  };
  let executed = 0;
  try {
    for (const change of [
      { maxPageSize: 0 },
      { maxFilterDepth: 0 },
      { maxConcurrent: 129 },
      { maxRequestBytes: 262145 },
      { users: {} },
      { groups: null },
      { authority: undefined },
      { unknown: true },
      ...[
        { patch: false },
        { filter: false },
        { bulk: true },
        { etag: 'yes' },
        { sort: null },
        { unknown: true },
      ].map((capabilities) => ({ capabilities: { ...settings.capabilities, ...capabilities } })),
    ])
      assert.throws(() => scimPlugin({ ...settings, ...change } as never), {
        code: 'EK_CONFIG_INVALID',
      });
    const accessor = { ...settings };
    Object.defineProperty(accessor, 'users', {
      get() {
        executed++;
        return settings.users;
      },
    });
    assert.throws(() => scimPlugin(accessor), { code: 'EK_CONFIG_INVALID' });
    const provider = { ...settings.users };
    Object.defineProperty(provider, 'get', {
      get() {
        executed++;
        return settings.users.get;
      },
    });
    assert.throws(() => scimPlugin({ ...settings, users: provider }), {
      code: 'EK_CONFIG_INVALID',
    });
    assert.equal(executed, 0);
    assert.equal(f.calls(), 0);
    const sink = new Writable({
      write(_chunk, _encoding, done) {
        done();
      },
    });
    const app = await createApplication({
      service: { name: 'scim-missing-auth', version: '1.0.0', environment: 'test' },
      plugins: [loggingPlugin({ destination: sink }), apiPlugin(), scimPlugin(settings)],
    });
    try {
      await assert.rejects(app.start());
    } finally {
      await app.stop();
      sink.destroy();
    }
    assert.equal(f.calls(), 0);
  } finally {
    await f.close();
  }
});
