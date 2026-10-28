// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { createApplication } from '@arkenivajs/core';
import { Runtime } from '../../dist/runtime.js';
import { samlPlugin, SAML_CAPABILITY } from '../../dist/index.js';
import type { SamlService } from '../../dist/index.js';
import { fixture } from '../fixture.js';

test('Cancellation after dispatching an atomic mutation reports an unknown outcome without a rollback claim', async () => {
  const runtime = new Runtime(),
    controller = new AbortController();
  let release!: () => void, entered!: () => void;
  const started = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const operation = runtime.run({ signal: controller.signal }, (call) =>
    call.mutate(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
          entered();
        }),
    ),
  );
  const checked = assert.rejects(operation, {
    code: 'EK_ABORTED',
    details: { outcome: 'unknown' },
  });
  await started;
  controller.abort();
  await checked;
  release();
  await runtime.close();
});

test('Timed-out provider work retains physical capacity until it actually settles', async (context) => {
  let now = performance.now();
  context.mock.method(performance, 'now', () => now);
  context.mock.timers.enable({ apis: ['setTimeout'] });
  const active: number[] = [],
    runtime = new Runtime(undefined, undefined, (count) => active.push(count));
  const releases: (() => void)[] = [];
  let entered!: () => void;
  const dispatched = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const pending = Array.from({ length: 8 }, () =>
    runtime.run({ timeoutMs: 2000 }, (call) =>
      call.step(
        'EK_BACKEND_UNAVAILABLE',
        () =>
          new Promise<void>((resolve) => {
            releases.push(resolve);
            if (releases.length === 8) entered();
          }),
      ),
    ),
  );
  // Establish physical provider ownership before expiring the public waiters.
  await dispatched;
  now += 2001;
  context.mock.timers.tick(2001);
  const results = await Promise.allSettled(pending);
  assert.equal(releases.length, 8);
  for (const result of results) {
    assert.equal(result.status, 'rejected');
    if (result.status === 'rejected')
      assert.equal((result.reason as { code: string }).code, 'EK_TIMEOUT');
  }
  await assert.rejects(
    runtime.run(undefined, async () => undefined),
    { code: 'EK_BACKEND_UNAVAILABLE' },
  );
  assert.equal(active.at(-1), 8);
  const closing = runtime.close();
  for (const release of releases) release();
  await closing;
  assert.equal(active.at(-1), 0);
  await assert.rejects(
    runtime.run(undefined, async () => undefined),
    { code: 'EK_RESOURCE_CLOSED' },
  );
});

test('Readiness and owner cancellation deny work and drain the underlying provider', async () => {
  const owner = new AbortController(),
    runtime = new Runtime(() => false, owner.signal);
  await assert.rejects(
    runtime.run(undefined, async () => undefined),
    { code: 'EK_LIFECYCLE_STATE' },
  );
  let release!: () => void, entered!: () => void;
  const started = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const result = runtime.run(
    undefined,
    (call) =>
      call.step(
        'EK_BACKEND_UNAVAILABLE',
        () =>
          new Promise<void>((resolve) => {
            release = resolve;
            entered();
          }),
      ),
    true,
  );
  const checked = assert.rejects(result, { code: 'EK_ABORTED' });
  await started;
  owner.abort('private-cancellation');
  await checked;
  release();
  await runtime.close();
});

test(
  'One plugin definition supports independent application owners and closes each service',
  { timeout: 20000 },
  async () => {
    const f = await fixture(),
      plugin = samlPlugin(f.settings);
    const applications = await Promise.all(
      [1, 2].map(() =>
        createApplication({
          service: { name: 'saml-lifecycle', version: '1.0.0', environment: 'test' },
          plugins: [plugin],
        }),
      ),
    );
    try {
      await Promise.all(applications.map((app) => app.start()));
      const [first, second] = applications.map((app) => app.resolve<SamlService>(SAML_CAPABILITY));
      assert.ok(first && second);
      assert.notEqual(first, second);
      await first.createMetadata();
      await applications[0]!.stop();
      await assert.rejects(first.createMetadata(), { code: 'EK_RESOURCE_CLOSED' });
      await second.createMetadata();
    } finally {
      await Promise.all(applications.map((app) => app.stop()));
      await f.close();
    }
  },
);
