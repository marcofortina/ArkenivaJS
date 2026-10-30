// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { redisPlugin } from '@arkenivajs/database-redis';
import { runPureWorker } from './pure-worker.mjs';
import {
  redisConnection,
  cleanupRedis,
  nativeRedis,
  verifyRedis,
  redisWorkload,
  completeRedis,
} from './redis-workload.mjs';

const key = Symbol('redis-comparison');
runPureWorker({
  name: 'redis',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  native: nativeRedis,
  framework(fixture) {
    const { prefix } = redisConnection(fixture);
    process.env.ARKENIVA_REDIS_COMPARISON_URL = fixture.url;
    return {
      plugins: [redisPlugin()],
      databases: {
        values: { driver: 'redis', connectionStringEnv: 'ARKENIVA_REDIS_COMPARISON_URL' },
      },
      key,
      plugin: {
        id: 'redis-comparison',
        version: '1.0.0',
        capabilities: new Set(),
        dependencies: ['database-redis'],
        init(context) {
          context.provide(key, {
            redis: context.require(COMPONENTS.redis),
            inspect: () => context.require(COMPONENTS.redis).native(),
            physical: (name) => prefix + name,
            workloadCalls: 0,
          });
        },
        async close(context) {
          await cleanupRedis(context.require(key), fixture);
        },
      },
    };
  },
  verify: verifyRedis,
  workload: redisWorkload,
  complete: completeRedis,
  close: (service) => service.close(),
});
