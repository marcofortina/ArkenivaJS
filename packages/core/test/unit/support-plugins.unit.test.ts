// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, COMPONENTS, KitError } from '@arkenivajs/core';
import { SUPPORT_PLUGINS, PREPARE_PLUGIN } from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';

const service = { name: 'support-test', version: '1.0.0', environment: 'test' as const };
const base = (id: string): ComposablePlugin => ({
  id,
  version: '1.0.0',
  capabilities: new Set(),
  init() {},
  close() {},
});
const supported = (plugin: ComposablePlugin): ComposablePlugin => plugin;
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;

test('EK-CORE-002 shared support metadata resolves once per application and preserves explicit ownership, preparation and cleanup order', async () => {
  let factories = 0,
    inits = 0;
  const events: string[] = [];
  const seen: unknown[] = [];
  const common: SupportPluginFactory = (options) => {
    factories++;
    assert.ok(Object.isFrozen(options));
    assert.ok(Object.isFrozen(options.plugins));
    assert.ok(Object.isFrozen(options.service));
    return {
      ...base('shared'),
      capabilities: new Set(['sql']),
      [PREPARE_PLUGIN](context) {
        events.push('prepare.' + context.options.service.name);
        return new Map([
          [COMPONENTS.sql, Object.freeze({ service: context.options.service.name })],
        ]);
      },
      init(context) {
        inits++;
        assert.equal(
          context.require<{ service: string }>(COMPONENTS.sql).service,
          context.options.service.name,
        );
        events.push('shared.init');
      },
      close() {
        events.push('shared.close');
      },
    } as ComposablePlugin;
  };
  const consumer = (id: string): ComposablePlugin => ({
    ...base(id),
    dependencies: ['shared'],
    [SUPPORT_PLUGINS]: [common],
    init(context) {
      inits++;
      seen.push(context.require(COMPONENTS.sql));
      events.push(id + '.init');
    },
    close() {
      events.push(id + '.close');
    },
  });
  const plugins = [consumer('first'), consumer('second')];
  const a = await createApplication({ service, plugins });
  const b = await createApplication({ service: { ...service, name: 'support-other' }, plugins });
  assert.equal(factories, 2);
  assert.equal(inits, 0);
  assert.notEqual(a.sql, b.sql);
  try {
    await a.start();
    await b.start();
    assert.equal(inits, 6);
    assert.equal(seen[0], seen[1]);
    assert.equal(seen[2], seen[3]);
    assert.notEqual(seen[0], seen[2]);
    await a.stop();
    assert.deepEqual(events.slice(-3), ['second.close', 'first.close', 'shared.close']);
  } finally {
    await a.stop();
    await b.stop();
  }
});

test('EK-CORE-002 support hooks cannot run before configuration validates or bypass explicit dependencies', async () => {
  let calls = 0,
    inits = 0;
  const common: SupportPluginFactory = () => {
    calls++;
    return {
      ...base('shared'),
      init() {
        inits++;
      },
    };
  };
  const owner = { ...base('owner'), dependencies: ['shared'], [SUPPORT_PLUGINS]: [common] };
  await assert.rejects(
    createApplication({ service: { ...service, name: 'INVALID' }, plugins: [owner] }),
    code('EK_CONFIG_INVALID'),
  );
  assert.equal(calls, 0);
  await assert.rejects(
    createApplication({ service, plugins: [{ ...owner, dependencies: [] }] }),
    code('EK_PLUGIN_DEPENDENCY'),
  );
  assert.equal(inits, 0);
  await assert.rejects(
    createApplication({ service, plugins: [owner, owner] }),
    code('EK_PLUGIN_DUPLICATE'),
  );
  assert.equal(calls, 1);
});

test('EK-CORE-002 malformed and asynchronous support factories reject without leaving unobserved rejections or running init', async () => {
  let initialized = 0;
  const invalid = [
    undefined,
    null,
    {},
    1,
    Array.from({ length: 65 }, () => () => base('too-many')),
    [1],
    [() => null],
    [
      () => {
        throw new Error('fake-factory-secret');
      },
    ],
    [
      async () => {
        throw new Error('fake-async-secret');
      },
    ],
    [
      () => ({
        ...base('bad\r'),
        init() {
          initialized++;
        },
      }),
    ],
  ];
  for (const value of invalid) {
    if (value === undefined) continue;
    const owner = { ...base('owner'), dependencies: ['shared'], [SUPPORT_PLUGINS]: value };
    await assert.rejects(
      createApplication({ service, plugins: [owner as never] }),
      code('EK_CONFIG_INVALID'),
    );
  }
  assert.equal(initialized, 0);
});

test('EK-CORE-002 distinct support definitions cannot overwrite ids or singleton capabilities and dependency cycles still fail', async () => {
  const common: SupportPluginFactory = () => base('shared');
  const owner = { ...base('owner'), dependencies: ['shared'], [SUPPORT_PLUGINS]: [common] };
  await assert.rejects(
    createApplication({ service, plugins: [owner, base('shared')] }),
    code('EK_PLUGIN_DUPLICATE'),
  );
  await assert.rejects(
    createApplication({
      service,
      plugins: [
        owner,
        { ...base('other'), dependencies: ['shared'], [SUPPORT_PLUGINS]: [() => base('shared')] },
      ],
    }),
    code('EK_PLUGIN_DUPLICATE'),
  );
  const sql: SupportPluginFactory = () => ({ ...base('shared'), capabilities: new Set(['sql']) });
  await assert.rejects(
    createApplication({
      service,
      plugins: [
        supported({ ...owner, [SUPPORT_PLUGINS]: [sql] }),
        { ...base('competing'), capabilities: new Set(['sql']) },
      ],
    }),
    code('EK_PLUGIN_DUPLICATE'),
  );
  const x: SupportPluginFactory = () => ({
    ...base('common.x'),
    dependencies: ['common.y'],
    [SUPPORT_PLUGINS]: [y],
  });
  const y: SupportPluginFactory = () => ({
    ...base('common.y'),
    dependencies: ['common.x'],
    [SUPPORT_PLUGINS]: [x],
  });
  await assert.rejects(
    createApplication({
      service,
      plugins: [
        supported({ ...base('owner'), dependencies: ['common.x'], [SUPPORT_PLUGINS]: [x] }),
      ],
    }),
    code('EK_PLUGIN_DEPENDENCY'),
  );
});

test('EK-CORE-002 recursive support expansion is bounded and initialized support resources roll back on consumer failure', async () => {
  const recursive =
    (index: number): SupportPluginFactory =>
    () => ({
      ...base('node.' + index),
      dependencies: ['node.' + (index + 1)],
      [SUPPORT_PLUGINS]: [recursive(index + 1)],
    });
  await assert.rejects(
    createApplication({
      service,
      plugins: [
        supported({
          ...base('owner'),
          dependencies: ['node.0'],
          [SUPPORT_PLUGINS]: [recursive(0)],
        }),
      ],
    }),
    code('EK_CONFIG_INVALID'),
  );
  let closed = 0;
  const primary = new Error('fake-consumer');
  const common: SupportPluginFactory = () => ({
    ...base('shared'),
    close() {
      closed++;
    },
  });
  const app = await createApplication({
    service,
    plugins: [
      supported({
        ...base('owner'),
        dependencies: ['shared'],
        [SUPPORT_PLUGINS]: [common],
        init() {
          throw primary;
        },
      }),
    ],
  });
  await assert.rejects(
    app.start(),
    (error) => code('EK_PLUGIN_FAILED')(error) && (error as KitError).cause === primary,
  );
  assert.equal(closed, 1);
  await app.stop();
  assert.equal(closed, 1);
});
