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
