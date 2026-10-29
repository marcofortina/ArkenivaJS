// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { inspect } from 'node:util';
import { createManagedSamlAdapter } from '../../dist/support.js';
import { Runtime } from '../../dist/runtime.js';
import { fixture } from '../fixture.js';

test(
  'Managed native SAML captures lifecycle authority, gates readiness and closes without aborting its owner',
  { timeout: 15000 },
  async () => {
    const f = await fixture(),
      owner = new AbortController();
    let ready = false,
      effects = 0;
    const predicate = () => ready;
    for (const field of ['bind', 'name', 'length'])
      Object.defineProperty(predicate, field, {
        get() {
          effects++;
          throw new Error('Executable readiness metadata');
        },
      });
    const adapter = createManagedSamlAdapter(f.settings, owner.signal, predicate);
    try {
      assert.equal(Object.isFrozen(adapter), true);
      assert.equal(Object.isFrozen(adapter.service), true);
      await adapter.bootstrap();
      await assert.rejects(() => adapter.service.createMetadata(), { code: 'EK_LIFECYCLE_STATE' });
      ready = true;
      assert.ok((await adapter.service.createMetadata()).includes('EntityDescriptor'));
      await adapter.close();
      assert.equal(owner.signal.aborted, false);
      await adapter.drain();
      await assert.rejects(() => adapter.service.createMetadata(), { code: 'EK_RESOURCE_CLOSED' });
      assert.equal(effects, 0);
    } finally {
      await adapter.drain();
      await f.close();
    }
  },
);

test(
  'Invalid owner/readiness inputs never gain readiness and callback failures retain no diagnostics',
  { timeout: 15000 },
  async () => {
    const f = await fixture(),
      owner = new AbortController();
    let effects = 0;
    const proxy = new Proxy(owner.signal, {
      get() {
        effects++;
        throw new Error('Untrusted owner');
      },
    });
    try {
      for (const value of [undefined, {}, Object.create(AbortSignal.prototype), proxy])
        assert.throws(
          () => createManagedSamlAdapter(f.settings, value as AbortSignal, () => true),
          { code: 'EK_SAML_CONFIGURATION' },
        );
      for (const value of [
        undefined,
        {},
        async () => true,
        new Proxy(() => true, {
          apply() {
            effects++;
            return true;
          },
        }),
      ])
        assert.throws(
          () => createManagedSamlAdapter(f.settings, owner.signal, value as () => boolean),
          { code: 'EK_SAML_CONFIGURATION' },
        );
      assert.equal(effects, 0);
      const marker = 'synthetic-readiness-diagnostic';
      for (const predicate of [
        () => {
          throw new Error(marker);
        },
        () => 'true',
        () => ({}),
        () => Promise.reject(new Error(marker)),
      ]) {
        const adapter = createManagedSamlAdapter(
          f.settings,
          owner.signal,
          predicate as () => boolean,
        );
        try {
          await assert.rejects(
            () => adapter.service.createMetadata(),
            (error) => {
              assert.equal(inspect(error).includes(marker), false);
              return (error as { code?: string }).code === 'EK_LIFECYCLE_STATE';
            },
          );
        } finally {
          await adapter.drain();
        }
      }
    } finally {
      await f.close();
    }
  },
);

test(
  'Owner abort rejects bootstrap promptly while managed drain retains the actual outstanding provider',
  { timeout: 15000 },
  async () => {
    const f = await fixture(),
      owner = new AbortController();
    let release!: () => void,
      entered!: () => void,
      drained = false;
    const started = new Promise<void>((resolve) => {
        entered = resolve;
      }),
      gate = new Promise<void>((resolve) => {
        release = resolve;
      }),
      original = f.settings.secretProvider.get,
      adapter = createManagedSamlAdapter(
        {
          ...f.settings,
          secretProvider: {
            async get(reference, options) {
              entered();
              await gate;
              return original(reference, options);
            },
          },
        },
        owner.signal,
        () => true,
      );
    try {
      const operation = adapter.bootstrap(),
        rejected = assert.rejects(operation, { code: 'EK_ABORTED' });
      await started;
      owner.abort('synthetic-private-owner-reason');
      await rejected;
      const draining = adapter.drain().then(() => {
        drained = true;
      });
      await new Promise<void>((resolve) => setImmediate(resolve));
      assert.equal(drained, false);
      await assert.rejects(() => adapter.service.createMetadata(), { code: 'EK_RESOURCE_CLOSED' });
      release();
      await draining;
      assert.equal(drained, true);
    } finally {
      release();
      await adapter.drain();
      await f.close();
    }
  },
);

test('A bounded close deadline cannot settle drain or reopen admission before actual provider settlement', async (context) => {
  let now = performance.now();
  context.mock.method(performance, 'now', () => now);
  context.mock.timers.enable({ apis: ['setTimeout'] });
  const active: number[] = [],
    runtime = new Runtime(undefined, undefined, (count) => active.push(count));
  let release!: () => void,
    entered!: () => void,
    drained = false;
  const started = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const operation = runtime.run(undefined, (call) =>
    call.step(
      'EK_BACKEND_UNAVAILABLE',
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
          entered();
        }),
    ),
  );
  const aborted = assert.rejects(operation, { code: 'EK_ABORTED' });
  await started;
  const closing = runtime.close(),
    timedOut = assert.rejects(closing, { code: 'EK_TIMEOUT' });
  await assert.rejects(
    runtime.run(undefined, async () => undefined),
    { code: 'EK_RESOURCE_CLOSED' },
  );
  const draining = runtime.drain().then(() => {
    drained = true;
  });
  await aborted;
  now += 5001;
  context.mock.timers.tick(5001);
  await timedOut;
  assert.equal(drained, false);
  assert.equal(active.at(-1), 1);
  release();
  await draining;
  assert.equal(active.at(-1), 0);
});
