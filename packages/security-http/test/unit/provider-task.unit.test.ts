// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import { createApplication, KitError } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { loggingPlugin } from '@arkenivajs/logging';
import { fixtureSettings } from './fixture.js';
import { providerTask } from '../../dist/provider-task.js';
import { capture } from '../../dist/settings.js';
import { securityHttpPlugin } from '../../dist/index.js';

test('Initial native-key work remains owned until its provider actually settles after cancellation', async () => {
  const f = fixtureSettings(),
    owner = new AbortController();
  let release!: () => void;
  f.state.holdHmac = new Promise<void>((resolve) => {
    release = resolve;
  });
  const tracker = providerTask(capture(f.settings), owner.signal),
    pending = tracker.load();
  await setImmediate();
  let closed = false;
  const closing = tracker.close().then(() => {
    closed = true;
  });
  owner.abort();
  await setImmediate();
  assert.equal(closed, false);
  await assert.rejects(tracker.load(), { code: 'EK_ABORTED' });
  release();
  await pending;
  await closing;
  assert.equal(closed, true);
});

test('Shutdown reports incomplete cleanup rather than claiming an uncooperative initial provider has stopped', async () => {
  const f = fixtureSettings();
  let release!: () => void,
    entered = false;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const input = {
    ...f.settings,
    csrfHmac: {
      ...f.settings.csrfHmac,
      async digest(...args: Parameters<typeof f.settings.csrfHmac.digest>) {
        entered = true;
        await held;
        return f.settings.csrfHmac.digest(...args);
      },
    },
  };
  const app = await createApplication({
    service: { name: 'http-security-initial-key', version: '1.0.0', environment: 'test' },
    logging: { level: 'silent' },
    plugins: [loggingPlugin(), apiPlugin(), securityHttpPlugin(input)],
  });
  const starting = app.start();
  void starting.catch(() => undefined);
  try {
    const deadline = performance.now() + 1000;
    while (!entered) {
      assert.ok(performance.now() < deadline);
      await setImmediate();
    }
    await assert.rejects(app.stop({ timeoutMs: 20 }), (error) => error instanceof KitError);
    await assert.rejects(
      starting,
      (error) => error instanceof KitError && Number(error.details.cleanupFailureCount) > 0,
    );
  } finally {
    release();
    await setImmediate();
    await app.stop().catch(() => undefined);
  }
});
