// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { createApplication, APPLICATION_SIGNAL } from '@arkenivajs/core';
import type { PluginContext } from '@arkenivajs/core';
import { HEALTH_PROBES, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin, PluginHealthProbe } from '@arkenivajs/core/support';

const service = { name: 'health-hooks-test', version: '1.0.0', environment: 'test' as const };

test('Kernel health callbacks retain original dependency scope, captured methods and immutable metadata', async () => {
  const resource = Symbol('owned.health-resource');
  let ownerContext: PluginContext | undefined,
    probes: readonly PluginHealthProbe[] = [],
    calls = 0;
  const owner: ComposablePlugin = {
    id: 'owner',
    version: '0.1.0',
    capabilities: new Set(),
    init(context) {
      ownerContext = context;
      context.provide(resource, 42);
    },
    close() {},
    health(context, options) {
      calls++;
      assert.equal(context, ownerContext);
      assert.equal(context.require(resource), 42);
      assert.equal(options.timeoutMs, 123);
      assert.throws(() => context.provide(Symbol('late'), 1), { code: 'EK_LIFECYCLE_STATE' });
      return true;
    },
  };
  const app = await createApplication({
    service,
    plugins: [
      {
        id: 'collector',
        version: '0.1.0',
        capabilities: new Set(['health']),
        init(context) {
          probes = context.require(HEALTH_PROBES);
        },
        close() {},
      },
      owner,
    ],
  });
  owner.health = () => false;
  await app.start();
  try {
    assert.deepEqual(
      probes.map((probe) => probe.name),
      ['plugin.owner'],
    );
    assert.equal(Object.isFrozen(probes), true);
    assert.equal(Object.isFrozen(probes[0]), true);
    assert.equal(await probes[0]!.check({ timeoutMs: 123 }), true);
    assert.equal(calls, 1);
  } finally {
    await app.stop();
  }
  await assert.rejects(probes[0]!.check({ timeoutMs: 123 }), { code: 'EK_RESOURCE_CLOSED' });
});

test('Kernel health ownership includes initialized recursive support plugins before a collector can probe them', async () => {
  let ready = false,
    probes: readonly PluginHealthProbe[] = [];
  const owner: ComposablePlugin = {
    id: 'consumer',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: ['support-resource'],
    [SUPPORT_PLUGINS]: [
      () => ({
        id: 'support-resource',
        version: '0.1.0',
        capabilities: new Set(),
        init() {
          ready = true;
        },
        close() {
          ready = false;
        },
        health: () => ready,
      }),
    ],
    init() {},
    close() {},
  };
  const app = await createApplication({
    service,
    plugins: [
      {
        id: 'collector',
        version: '0.1.0',
        capabilities: new Set(['health']),
        async init(context) {
          probes = context.require(HEALTH_PROBES);
          assert.equal(await probes[0]!.check({}), true);
        },
        close() {},
      },
      owner,
    ],
  });
  await app.start();
  assert.deepEqual(
    probes.map((probe) => probe.name),
    ['plugin.support-resource'],
  );
  await app.stop();
});

test('Kernel health metadata cannot be read without its capability or replaced by application plugins', async () => {
  for (const key of [HEALTH_PROBES, APPLICATION_SIGNAL]) {
    const app = await createApplication({
      service,
      plugins: [
        {
          id: 'replacement',
          version: '0.1.0',
          capabilities: new Set(),
          init(context) {
            assert.throws(() => context.provide(key, {}), { code: 'EK_PLUGIN_DEPENDENCY' });
            assert.throws(() => context.require(HEALTH_PROBES), { code: 'EK_PLUGIN_DEPENDENCY' });
          },
          close() {},
        },
      ],
    });
    await app.start();
    await app.stop();
  }
  await assert.rejects(
    createApplication({
      service,
      plugins: [
        {
          id: 'invalid-hook',
          version: '0.1.0',
          capabilities: new Set(),
          init() {},
          close() {},
          health: true,
        } as never,
      ],
    }),
    { code: 'EK_CONFIG_INVALID' },
  );
});

test('Kernel rejects invalid plugin evidence and late successful probes after their owner stops', async () => {
  let probes: readonly PluginHealthProbe[] = [],
    invalid = true,
    release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const owner: ComposablePlugin = {
    id: 'owner',
    version: '0.1.0',
    capabilities: new Set(),
    init() {},
    close() {},
    async health() {
      if (invalid) return 'ready' as never;
      await gate;
      return true;
    },
  };
  const app = await createApplication({
    service,
    plugins: [
      owner,
      {
        id: 'collector',
        version: '0.1.0',
        capabilities: new Set(['health']),
        init(context) {
          probes = context.require(HEALTH_PROBES);
        },
        close() {},
      },
    ],
  });
  await app.start();
  try {
    await assert.rejects(probes[0]!.check({}), { code: 'EK_HEALTH_NOT_READY' });
    invalid = false;
    const observed = assert.rejects(probes[0]!.check({}), { code: 'EK_RESOURCE_CLOSED' });
    await delay(0);
    await app.stop();
    release();
    await observed;
  } finally {
    release();
    await app.stop();
  }
});

test('Kernel health capture ignores custom bind metadata and preserves actual dependency failure', async () => {
  let calls = 0,
    binds = 0;
  const owner: ComposablePlugin = {
    id: 'unavailable-owner',
    version: '0.1.0',
    capabilities: new Set(),
    init() {},
    close() {},
    health() {
      assert.equal(this, owner);
      calls++;
      return false;
    },
  };
  Object.defineProperty(owner.health, 'bind', {
    value: () => {
      binds++;
      return () => true;
    },
  });
  let probes: readonly PluginHealthProbe[] = [];
  const app = await createApplication({
    service,
    plugins: [
      owner,
      {
        id: 'collector',
        version: '0.1.0',
        capabilities: new Set(['health']),
        init(context) {
          probes = context.require(HEALTH_PROBES);
        },
        close() {},
      },
    ],
  });
  owner.health = () => true;
  try {
    await app.start();
    assert.equal(await probes[0]!.check({}), false);
    assert.equal(calls, 1);
    assert.equal(binds, 0);
  } finally {
    await app.stop();
  }
});
