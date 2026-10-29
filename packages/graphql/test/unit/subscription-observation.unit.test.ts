// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AsyncLocalStorage, AsyncResource } from 'node:async_hooks';
import { setImmediate } from 'node:timers/promises';
import type { Telemetry } from '@arkenivajs/core';
import { capture } from '../../dist/policy.js';
import { Operation } from '../../dist/operation.js';
import { traceSubscriptionScope } from '../../dist/subscription-observation.js';

test('Subscription trace context retains physical work after public abort and excludes unrelated callers', async () => {
  const storage = new AsyncLocalStorage<string>();
  const parents: (string | undefined)[] = [];
  let started = 0,
    ended = 0;
  const telemetry: Telemetry = {
    measure: async (_name, work) => work(),
    withSpan: async (_name, work) => {
      parents.push(storage.getStore());
      started++;
      try {
        return await storage.run('owned-event', work);
      } finally {
        ended++;
      }
    },
    addCounter() {},
    recordHistogram() {},
    setGauge() {},
    async flush() {},
  };
  const parent = storage.run('owned-upgrade', () => new AsyncResource('TestSubscriptionParent'));
  const limits = capture({
    schema: 'type Query { ping: String }',
    resolvers: {},
    security: { authorizeField: () => true },
  }).security.limits;
  const scope = new Operation(
    { requestId: 'private-request' },
    limits,
    new AbortController().signal,
  );
  await storage.run('unrelated-request', () => traceSubscriptionScope(telemetry, parent, scope));
  assert.deepEqual(parents, ['owned-upgrade']);
  assert.equal(storage.getStore(), undefined);
  let release!: () => void, entered!: () => void;
  const began = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const physical = new Promise<void>((resolve) => {
    release = resolve;
  });
  const publicWork = scope.run(async () => {
    assert.equal(storage.getStore(), 'owned-event');
    entered();
    await physical;
    assert.equal(storage.getStore(), 'owned-event');
  });
  await began;
  scope.abort();
  scope.end();
  await assert.rejects(publicWork, { code: 'EK_GQL_TIMEOUT' });
  assert.equal(started, 1);
  assert.equal(ended, 0, 'Public abort does not finish a span with pending physical work');
  assert.equal(storage.getStore(), undefined);
  release();
  await scope.completion;
  await setImmediate();
  assert.equal(ended, 1);
  assert.equal(scope.runInContext, undefined);
  parent.emitDestroy();
});
