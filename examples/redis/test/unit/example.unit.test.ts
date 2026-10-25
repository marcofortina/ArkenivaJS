// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { RedisProvider, OperationOptions } from '@arkenivajs/core';
import { cacheOrder, runRedisCacheExample } from '../../dist/main.js';

test('The Redis cache consumer preserves true/false NX outcomes and a string DTO without overwriting an existing entry', async () => {
  let stored: string | undefined;
  const port: Pick<RedisProvider, 'get' | 'set'> = {
    async set(
      key: string,
      value: string,
      options?: OperationOptions & { ttlMs?: number; onlyIfAbsent?: boolean },
    ) {
      assert.equal(key, 'tenant-a:order');
      assert.deepEqual(options, { ttlMs: 5000, onlyIfAbsent: true });
      if (stored !== undefined) return false;
      stored = value;
      return true;
    },
    async get() {
      return stored ?? null;
    },
  };
  const first = await cacheOrder(port, 'tenant-a:order');
  const second = await cacheOrder(port, 'tenant-a:order');
  assert.equal(first.accepted, true);
  assert.equal(second.accepted, false);
  assert.equal(first.value, second.value);
  assert.deepEqual(JSON.parse(first.value!), { id: '42', total: '5.25' });
  assert.ok(Object.isFrozen(first));
  const failure = new Error('Backend failed');
  await assert.rejects(
    cacheOrder(
      {
        ...port,
        async set() {
          throw failure;
        },
      },
      'tenant-a:order',
    ),
    (error) => error === failure,
  );
});

test('The Redis consumer refuses implicit live access and prints safe CLI errors', async () => {
  const previous = {
    disposable: process.env.ARKENIVA_REDIS_DISPOSABLE,
    url: process.env.ARKENIVA_REDIS_URL,
  };
  try {
    delete process.env.ARKENIVA_REDIS_DISPOSABLE;
    delete process.env.ARKENIVA_REDIS_URL;
    await assert.rejects(
      runRedisCacheExample(),
      (e) => e instanceof KitError && e.code === 'EK_CONFIG_INVALID',
    );
    process.env.ARKENIVA_REDIS_DISPOSABLE = '1';
    await assert.rejects(
      runRedisCacheExample(),
      (e) => e instanceof KitError && e.code === 'EK_CONFIG_MISSING',
    );
    await assert.rejects(
      promisify(execFile)(process.execPath, ['dist/main.js'], { env: process.env }),
      (error) => {
        assert.ok(error && typeof error === 'object' && 'stderr' in error);
        const safe = JSON.parse(String(error.stderr));
        assert.equal(safe.code, 'EK_CONFIG_MISSING');
        assert.equal(safe.cause, undefined);
        assert.equal(safe.stack, undefined);
        return true;
      },
    );
  } finally {
    for (const [key, value] of [
      ['ARKENIVA_REDIS_DISPOSABLE', previous.disposable],
      ['ARKENIVA_REDIS_URL', previous.url],
    ] as const)
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
  }
});
