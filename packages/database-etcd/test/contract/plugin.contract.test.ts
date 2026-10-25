// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, KitError } from '@arkenivajs/core';
import type { Plugin } from '@arkenivajs/core';
import { etcdPlugin } from '@arkenivajs/database-etcd';

const service = { name: 'etcd-contract', version: '1.0.0', environment: 'test' as const };
const factory: () => Plugin = etcdPlugin;
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;

test('EK-CORE-002 etcd prepares a frozen typed facade without resolving its connection environment', async () => {
  const plugin = factory();
  assert.ok(plugin.capabilities.has('etcd'));
  assert.ok(plugin.capabilities.has('database.etcd'));
  const app = await createApplication({
    service,
    plugins: [plugin],
    databases: {
      configuration: { driver: 'etcd', connectionStringEnv: 'ARKENIVA_UNUSED_ETCD_CONTRACT' },
    },
  });
  const provider = app.etcd!;
  assert.equal(app.state, 'CREATED');
  assert.ok(Object.isFrozen(provider));
  await assert.rejects(provider.get('key'), code('EK_LIFECYCLE_STATE'));
  await assert.rejects(provider.put('key', new Uint8Array()), code('EK_LIFECYCLE_STATE'));
  await assert.rejects(provider.delete('key'), code('EK_LIFECYCLE_STATE'));
  await assert.rejects(provider.watch('prefix'), code('EK_LIFECYCLE_STATE'));
  await assert.rejects(provider.grantLease(1), code('EK_LIFECYCLE_STATE'));
  await assert.rejects(
    provider.compareAndSwap({ key: 'key', expectedRevision: 0n, value: new Uint8Array() }),
    code('EK_LIFECYCLE_STATE'),
  );
  assert.throws(() => provider.native(), code('EK_LIFECYCLE_STATE'));
  await app.stop();
  await assert.rejects(provider.get('key'), code('EK_RESOURCE_CLOSED'));
  assert.throws(() => provider.native(), code('EK_RESOURCE_CLOSED'));
});

test('EK-CONF-001 etcd fails missing definitions before native startup and duplicate singleton definitions at creation', async () => {
  const app = await createApplication({ service, plugins: [factory()] });
  await assert.rejects(
    app.start(),
    (error) =>
      error instanceof KitError &&
      error.cause instanceof KitError &&
      error.cause.code === 'EK_CONFIG_MISSING',
  );
  await app.stop();
  assert.equal(app.state, 'CLOSED');
  await assert.rejects(
    createApplication({
      service,
      plugins: [factory()],
      databases: {
        a: { driver: 'etcd', endpoints: ['http://localhost:2379'] },
        b: { driver: 'etcd', endpoints: ['http://localhost:2379'] },
      },
    }),
    code('EK_CONFIG_INVALID'),
  );
});
