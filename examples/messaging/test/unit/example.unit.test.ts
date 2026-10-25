// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { orderDTO, runMessagingExample } from '../../dist/main.js';

test('Messaging consumer validates business identity and projects explicit public fields', () => {
  assert.deepEqual(orderDTO({ orderId: '42', private: 'omit' }), { orderId: '42' });
  assert.ok(Object.isFrozen(orderDTO({ orderId: '42' })));
  for (const value of [null, {}, { orderId: 42 }, { orderId: '' }, new Date()])
    assert.throws(() => orderDTO(value), { code: 'EK_CONFIG_INVALID' });
});

test('Messaging consumer refuses implicit broker use and emits only safe CLI errors', async () => {
  const flag = process.env.ARKENIVA_NATS_DISPOSABLE,
    url = process.env.ARKENIVA_NATS_URL;
  try {
    delete process.env.ARKENIVA_NATS_DISPOSABLE;
    delete process.env.ARKENIVA_NATS_URL;
    await assert.rejects(runMessagingExample(), { code: 'EK_CONFIG_INVALID' });
    process.env.ARKENIVA_NATS_DISPOSABLE = '1';
    await assert.rejects(runMessagingExample(), { code: 'EK_CONFIG_MISSING' });
    await assert.rejects(
      promisify(execFile)(process.execPath, ['dist/main.js'], { env: process.env }),
      (cause: unknown) => {
        assert.ok(cause && typeof cause === 'object' && 'stderr' in cause);
        const safe = JSON.parse(String(cause.stderr));
        assert.equal(safe.code, 'EK_CONFIG_MISSING');
        assert.equal(safe.stack, undefined);
        assert.equal(safe.cause, undefined);
        return true;
      },
    );
  } finally {
    if (flag === undefined) delete process.env.ARKENIVA_NATS_DISPOSABLE;
    else process.env.ARKENIVA_NATS_DISPOSABLE = flag;
    if (url === undefined) delete process.env.ARKENIVA_NATS_URL;
    else process.env.ARKENIVA_NATS_URL = url;
  }
});
