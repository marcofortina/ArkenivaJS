// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication } from '@arkenivajs/core';
import { HEALTH_PROBES } from '@arkenivajs/core/support';
import type { PluginHealthProbe } from '@arkenivajs/core/support';
import { redisPlugin } from '@arkenivajs/database-redis';

test(
  'Real redis health probes use initialized owned resources before public activation and reject stale ownership',
  { timeout: 20000 },
  async () => {
    assert.equal(
      process.env.ARKENIVA_REDIS_DISPOSABLE,
      '1',
      'An explicitly disposable fixture is required',
    );
    assert.ok(process.env.ARKENIVA_REDIS_URL);
    let probes: readonly PluginHealthProbe[] = [];
    const app = await createApplication({
      service: { name: 'redis-health-test', version: '1.0.0', environment: 'test' },
      databases: { main: { driver: 'redis', connectionStringEnv: 'ARKENIVA_REDIS_URL' } },
      plugins: [
        {
          id: 'health-test-collector',
          version: '0.1.0',
          capabilities: new Set(['health']),
          async init(context) {
            probes = context.require(HEALTH_PROBES);
            assert.deepEqual(
              probes.map((probe) => probe.name),
              ['plugin.database-redis'],
            );
            assert.equal(app.state, 'INITIALIZING');
            assert.equal(await probes[0]!.check({ timeoutMs: 2000 }), true);
          },
          close() {},
        },
        redisPlugin(),
      ],
    });
    try {
      await app.start();
      assert.equal(await probes[0]!.check({ timeoutMs: 2000 }), true);
      await assert.rejects(probes[0]!.check({ signal: AbortSignal.abort(), timeoutMs: 2000 }));
    } finally {
      await app.stop();
    }
    await assert.rejects(probes[0]!.check({ timeoutMs: 2000 }), { code: 'EK_RESOURCE_CLOSED' });
  },
);
