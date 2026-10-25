// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import { HEALTH_PROBES } from '@arkenivajs/core/support';
import type { PluginHealthProbe } from '@arkenivajs/core/support';
import { oraclePlugin } from '@arkenivajs/database-oracle';
import { OracleConnection } from '../../dist/connection.js';

test('Oracle health contract probes every owned pool before activation and preserves false, errors and closed ownership', async (context) => {
  const variable = 'ARKENIVA_ORACLE_HEALTH_CONTRACT';
  const previous = process.env[variable],
    calls: string[] = [],
    closed: string[] = [];
  let state = 'ready',
    probes: readonly PluginHealthProbe[] = [];
  context.mock.method(
    OracleConnection,
    'create',
    async (name: string) =>
      ({
        async queryOne() {
          return { healthy: '1' };
        },
        async query() {
          throw new Error('A health hook must not execute a business query');
        },
        async execute() {
          throw new Error('A health hook must not execute a mutation');
        },
        async transaction() {
          throw new Error('A health hook must not start a transaction');
        },
        stats() {
          return {};
        },
        native() {
          throw new Error('A health hook must not expose the native pool');
        },
        async ping(options: OperationOptions) {
          assert.equal(options.timeoutMs, 1000);
          calls.push(name);
          if (state === 'error') throw new Error('Oracle dependency failed');
          return state !== 'offline' || name !== 'two';
        },
        async close() {
          closed.push(name);
        },
      }) as unknown as OracleConnection,
  );
  process.env[variable] = 'oracle://app:pw@localhost/FREE';
  try {
    const definition = { driver: 'oracle' as const, connectionStringEnv: variable };
    const app = await createApplication({
      service: { name: 'oracle-health-contract', version: '1.0.0', environment: 'test' },
      databases: { one: definition, two: definition },
      plugins: [
        {
          id: 'health-test-collector',
          version: '0.1.0',
          capabilities: new Set(['health']),
          async init(context) {
            probes = context.require(HEALTH_PROBES);
            assert.equal(app.state, 'INITIALIZING');
            assert.equal(await probes[0]!.check({ timeoutMs: 1000 }), true);
          },
          close() {},
        },
        oraclePlugin(),
      ],
    });
    try {
      await app.start();
      assert.deepEqual(calls, ['one', 'two']);
      state = 'offline';
      assert.equal(await probes[0]!.check({ timeoutMs: 1000 }), false);
      state = 'error';
      await assert.rejects(probes[0]!.check({ timeoutMs: 1000 }), /Oracle dependency failed/);
    } finally {
      await app.stop();
    }
    assert.deepEqual(closed.sort(), ['one', 'two']);
    await assert.rejects(probes[0]!.check({ timeoutMs: 1000 }), { code: 'EK_RESOURCE_CLOSED' });
  } finally {
    if (previous === undefined) delete process.env[variable];
    else process.env[variable] = previous;
  }
});
