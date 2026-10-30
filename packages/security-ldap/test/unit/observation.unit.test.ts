// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import test from 'node:test';
import { setImmediate } from 'node:timers/promises';
import type { Logger, Telemetry } from '@arkenivajs/core';
import { recorder } from '../../dist/observation.js';

test('LDAP diagnostic callbacks retain bounded measurements and classify timeouts without secret fields', () => {
  const records: {
      name: string;
      value: number;
      attributes?: Readonly<Record<string, string | number | boolean>>;
    }[] = [],
    logs: unknown[] = [];
  const write = (
    name: string,
    value: number,
    attributes?: Readonly<Record<string, string | number | boolean>>,
  ) => {
    records.push({ name, value, ...(attributes ? { attributes } : {}) });
  };
  const telemetry = { addCounter: write, recordHistogram: write } as unknown as Telemetry,
    logger = {
      debug(_message: string, attributes: unknown) {
        logs.push(attributes);
      },
    } as unknown as Logger,
    observed = recorder({ telemetry, logger });
  observed.measure('bind', 1.5);
  observed.measure('search', 1);
  observed.measure('depth', 2);
  observed.complete('find', 'ok', 3);
  observed.complete('verify', 'error', 4);
  observed.complete('ping', 'timeout', 5);
  assert.equal(records.find((row) => row.name === 'ldap.bind.duration.ms')?.value, 1.5);
  assert.equal(records.find((row) => row.name === 'ldap.search.count')?.value, 1);
  assert.equal(records.find((row) => row.name === 'ldap.group.depth')?.value, 2);
  assert.equal(records.find((row) => row.name === 'ldap.timeouts')?.value, 1);
  assert.deepEqual(
    records
      .filter((row) => row.name === 'ldap.operation.duration.ms')
      .map((row) => row.attributes?.['ldap.outcome']),
    ['ok', 'error', 'timeout'],
  );
  assert.ok(
    logs.every(
      (row) =>
        Object.keys(row as object)
          .sort()
          .join() === 'operation,outcome',
    ),
  );
});

test('Throwing and rejecting LDAP diagnostic providers never escape measurement or completion callbacks', async () => {
  for (const asynchronous of [false, true]) {
    let calls = 0;
    const fail = () => {
        calls++;
        if (asynchronous) return Promise.reject(new Error('Private diagnostic rejection'));
        throw new Error('Private diagnostic failure');
      },
      observed = recorder({
        logger: { debug: fail } as unknown as Logger,
        telemetry: { addCounter: fail, recordHistogram: fail } as unknown as Telemetry,
      });
    assert.doesNotThrow(() => {
      observed.measure('bind', 1);
      observed.measure('search', 1);
      observed.measure('depth', 1);
      observed.complete('find', 'ok', 1);
      observed.complete('verify', 'error', 1);
      observed.complete('ping', 'timeout', 1);
    });
    await setImmediate();
    assert.equal(calls, 10);
  }
  const absent = recorder({});
  assert.doesNotThrow(() => {
    absent.measure('search', 1);
    absent.measure('depth', 1);
    absent.complete('ping', 'timeout', 1);
  });
});
