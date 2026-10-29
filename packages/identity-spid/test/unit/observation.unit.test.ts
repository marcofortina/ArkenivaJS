// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import { KitError } from '@arkenivajs/core';
import type { Logger, Telemetry } from '@arkenivajs/core';
import { recorder } from '../../dist/observation.js';

test('Synchronous and asynchronous diagnostic failures cannot escape federation recording', async () => {
  for (const mode of ['throw', 'reject'] as const) {
    let calls = 0;
    const unavailable = () => {
      calls++;
      if (mode === 'throw') throw new Error('Unavailable diagnostic sink');
      return Promise.reject(new Error('Unavailable diagnostic sink'));
    };
    const telemetry: Telemetry = {
        async measure(_name, work) {
          return work();
        },
        async withSpan(_name, work) {
          return work();
        },
        addCounter: unavailable,
        recordHistogram: unavailable,
        setGauge: unavailable,
        async flush() {},
      },
      logger: Logger = {
        trace: unavailable,
        debug: unavailable,
        info: unavailable,
        warn: unavailable,
        error: unavailable,
        fatal: unavailable,
        child() {
          return logger;
        },
        setLevel() {},
        async flush() {},
      };
    const record = recorder({ telemetry, logger });
    assert.doesNotThrow(() => record.complete('begin_authentication'));
    assert.doesNotThrow(() =>
      record.complete(
        'consume_authentication',
        new KitError({ code: 'EK_EID_FEDERATION', message: 'Private protocol failure' }),
      ),
    );
    await setImmediate();
    assert.equal(calls, 5);
  }
});

test('Diagnostics never read an upstream error message, cause or detail', () => {
  let inspected = 0;
  const error = Object.create(
    new KitError({ code: 'EK_EID_FEDERATION', message: 'Private protocol failure' }),
  ) as KitError;
  for (const key of ['message', 'cause', 'details'])
    Object.defineProperty(error, key, {
      get() {
        inspected++;
        throw new Error('Sensitive error inspection');
      },
    });
  const record = recorder({});
  assert.doesNotThrow(() => record.complete('verify_federation_trust', error));
  assert.equal(inspected, 0);
});

test('Italian diagnostic classification never executes error getters or proxy traps', () => {
  let executions = 0;
  const trap = () => {
    executions++;
    throw new Error('Untrusted diagnostic access');
  };
  for (const system of ['spid', 'cie'] as const) {
    const error = Object.create(
      new KitError({ code: 'EK_EID_FEDERATION', message: 'Private failure' }),
    ) as KitError;
    Object.defineProperty(error, 'code', { get: trap });
    const record = recorder({}, system);
    for (const input of [
      error,
      new Proxy(error, { get: trap, getPrototypeOf: trap }),
      { code: '__proto__' },
      null,
      'private provider failure',
    ])
      assert.doesNotThrow(() => record.complete('consume_authentication', input, 25));
  }
  assert.equal(executions, 0);
});

test('CIE diagnostic failures preserve the caller result and do not emit invalid or fabricated duration values', async () => {
  for (const mode of ['throw', 'reject'] as const) {
    let calls = 0;
    const unavailable = () => {
      calls++;
      if (mode === 'throw') throw new Error('Unavailable observer');
      return Promise.reject(new Error('Unavailable observer'));
    };
    const telemetry: Telemetry = {
      async measure(_name, work) {
        return work();
      },
      async withSpan(_name, work) {
        return work();
      },
      addCounter: unavailable,
      recordHistogram: unavailable,
      setGauge: unavailable,
      async flush() {},
    };
    const record = recorder({ telemetry }, 'cie');
    assert.doesNotThrow(() => record.complete('begin_authentication', undefined, 100));
    assert.doesNotThrow(() =>
      record.complete(
        'verify_federation_trust',
        new KitError({ code: 'EK_EID_FEDERATION', message: 'Private provider diagnostic' }),
        1,
      ),
    );
    for (const duration of [undefined, NaN, Infinity, -1])
      assert.doesNotThrow(() => record.complete('consume_authentication', undefined, duration));
    await setImmediate();
    assert.equal(calls, 3);
  }
});
