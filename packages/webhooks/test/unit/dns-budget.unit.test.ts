// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate as immediate } from 'node:timers/promises';
import { within } from '@arkenivajs/core/support';
import { DnsBudget } from '../../dist/dns-budget.js';

test('A timed-out DNS waiter retains native lookup capacity until the actual resolution settles', async () => {
  let release!: () => void,
    started = 0;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const budget = new DnsBudget(
    1,
    () => {},
    async () => {
      started++;
      await gate;
      return [{ address: '127.0.0.1', family: 4 }];
    },
  );
  const task = budget.resolve('localhost');
  await assert.rejects(
    within(() => task, { timeoutMs: 5 }),
    { code: 'EK_TIMEOUT' },
  );
  assert.equal(started, 1);
  assert.equal(budget.pending.size, 1);
  assert.throws(() => budget.resolve('localhost'), { code: 'EK_BACKEND_UNAVAILABLE' });
  release();
  await task;
  await immediate();
  assert.equal(budget.pending.size, 0);
  await budget.resolve('localhost');
  assert.equal(started, 2);
});
test('Closed DNS ownership blocks a new lookup and drains the real outstanding lookup without publishing late addresses', async () => {
  let release!: () => void,
    closed = false;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const budget = new DnsBudget(
    1,
    () => {
      if (closed) throw new Error('Owned DNS budget closed');
    },
    async () => {
      await gate;
      return [{ address: '127.0.0.1', family: 4 }];
    },
  );
  const task = budget.resolve('localhost');
  void task.catch(() => undefined);
  await immediate();
  closed = true;
  let drained = false;
  const draining = budget.drain().then(() => {
    drained = true;
  });
  assert.throws(() => budget.resolve('localhost'));
  await immediate();
  assert.equal(drained, false);
  release();
  await draining;
  await assert.rejects(task);
  assert.equal(budget.pending.size, 0);
});
