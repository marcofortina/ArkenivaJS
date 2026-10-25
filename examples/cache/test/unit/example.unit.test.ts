// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { customerDTO, runCacheExample } from '../../dist/main.js';

test('Cache consumer validates its business DTO and projects public JSON fields explicitly', () => {
  const value = customerDTO({ id: 'customer-42', name: 'Ada', internal: 'private' });
  assert.deepEqual(JSON.parse(JSON.stringify(value)), { id: 'customer-42', name: 'Ada' });
  assert.equal(Object.isFrozen(value), true);
  for (const input of [
    null,
    {},
    { id: 42, name: 'Ada' },
    { id: 'customer-42', name: false },
    new Date(),
  ])
    assert.throws(() => customerDTO(input), { code: 'EK_CONFIG_INVALID' });
});

test('Cache consumer requires explicit live authorization and emits safe CLI errors', async () => {
  const disposable = process.env.ARKENIVA_REDIS_DISPOSABLE,
    url = process.env.ARKENIVA_REDIS_URL;
  try {
    delete process.env.ARKENIVA_REDIS_DISPOSABLE;
    delete process.env.ARKENIVA_REDIS_URL;
    await assert.rejects(runCacheExample(), { code: 'EK_CONFIG_INVALID' });
    process.env.ARKENIVA_REDIS_DISPOSABLE = '1';
    await assert.rejects(runCacheExample(), { code: 'EK_CONFIG_MISSING' });
    await assert.rejects(
      promisify(execFile)(process.execPath, ['dist/main.js'], { env: process.env }),
      (cause: unknown) => {
        assert.ok(cause && typeof cause === 'object' && 'stderr' in cause);
        const safe = JSON.parse(String(cause.stderr));
        assert.equal(safe.code, 'EK_CONFIG_MISSING');
        assert.equal(safe.cause, undefined);
        assert.equal(safe.stack, undefined);
        return true;
      },
    );
  } finally {
    if (disposable === undefined) delete process.env.ARKENIVA_REDIS_DISPOSABLE;
    else process.env.ARKENIVA_REDIS_DISPOSABLE = disposable;
    if (url === undefined) delete process.env.ARKENIVA_REDIS_URL;
    else process.env.ARKENIVA_REDIS_URL = url;
  }
});
