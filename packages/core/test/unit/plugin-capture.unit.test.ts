// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication } from '@arkenivajs/core';
import type { ComposablePlugin } from '@arkenivajs/core/support';
import {
  PREPARE_PLUGIN,
  ACTIVATE_PLUGIN,
  DRAIN_PLUGIN,
  SUPPORT_PLUGINS,
} from '@arkenivajs/core/support';

const service = { name: 'plugin-capture', version: '1.0.0', environment: 'test' as const };

test('Kernel captures every lifecycle callback without reading bind, call or apply metadata', async () => {
  const events: string[] = [];
  let metadataReads = 0;
  const owner: ComposablePlugin = {
    id: 'owner',
    version: '0.1.0',
    capabilities: new Set(),
    [PREPARE_PLUGIN]() {
      assert.equal(this, owner);
      events.push('prepare');
      return new Map();
    },
    init() {
      assert.equal(this, owner);
      events.push('init');
    },
    [ACTIVATE_PLUGIN]() {
      assert.equal(this, owner);
      events.push('activate');
    },
    [DRAIN_PLUGIN]() {
      assert.equal(this, owner);
      events.push('drain');
    },
    close() {
      assert.equal(this, owner);
      events.push('close');
    },
  };
  for (const callback of [
    owner.init,
    owner.close,
    owner[PREPARE_PLUGIN]!,
    owner[ACTIVATE_PLUGIN]!,
    owner[DRAIN_PLUGIN]!,
  ]) {
    for (const name of ['bind', 'call', 'apply'])
      Object.defineProperty(callback, name, {
        get() {
          metadataReads++;
          throw new Error('Function metadata must not execute');
        },
      });
  }
  const app = await createApplication({ service, plugins: [owner] });
  owner.init = () => {
    throw new Error('A replacement callback must not execute');
  };
  owner.close = owner.init;
  owner[PREPARE_PLUGIN] = owner.init as never;
  owner[ACTIVATE_PLUGIN] = owner.init;
  owner[DRAIN_PLUGIN] = owner.init;
  await app.start();
  await app.stop();
  assert.deepEqual(events, ['prepare', 'init', 'activate', 'drain', 'close']);
  assert.equal(metadataReads, 0);
});

test('Kernel rejects executable plugin metadata before opening resources', async () => {
  let effects = 0;
  const trap = () => {
    effects++;
    throw new Error('Plugin metadata must not execute');
  };
  const base = () => ({
    id: 'owner',
    version: '0.1.0',
    capabilities: new Set<string>(),
    init() {},
    close() {},
  });
  const invalid: unknown[] = [
    new Proxy(base(), { get: trap, ownKeys: trap, getOwnPropertyDescriptor: trap }),
    Object.create(
      new Proxy(base(), { get: trap, getOwnPropertyDescriptor: trap, getPrototypeOf: trap }),
    ),
  ];
  for (const name of [
    'id',
    'version',
    'capabilities',
    'dependencies',
    'init',
    'close',
    'health',
    PREPARE_PLUGIN,
    ACTIVATE_PLUGIN,
    DRAIN_PLUGIN,
    SUPPORT_PLUGINS,
  ])
    invalid.push(Object.defineProperty(base(), name, { get: trap }));
  for (const name of ['init', 'close', 'health', PREPARE_PLUGIN, ACTIVATE_PLUGIN, DRAIN_PLUGIN])
    invalid.push({ ...base(), [name]: new Proxy(() => true, { apply: trap }) });
  invalid.push(
    Array.from({ length: 33 }).reduce<object>(
      (previous) => Object.create(previous) as object,
      base(),
    ),
  );
  for (const plugin of invalid)
    await assert.rejects(createApplication({ service, plugins: [plugin as never] }), {
      code: 'EK_CONFIG_INVALID',
    });
  assert.equal(effects, 0);
});
