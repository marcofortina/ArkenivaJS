// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { COMPONENTS } from '@arkenivajs/core';
import { redisPlugin } from '@arkenivajs/database-redis';
import { cachePlugin } from '@arkenivajs/cache';
import { runPureWorker } from './pure-worker.mjs';
import {
  cacheKeys,
  cacheConnection,
  nativeCache,
  verifyCache,
  cacheWorkload,
} from './cache-workload.mjs';

const key = Symbol('cache-comparison');
runPureWorker({
  name: 'cache',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  native: nativeCache,
  framework(fixture) {
    const { prefix } = cacheConnection(fixture);
    process.env.ARKENIVA_CACHE_COMPARISON_URL = fixture.url;
    return {
      plugins: [redisPlugin(), cachePlugin({ namespace: fixture.namespace })],
      databases: {
        values: { driver: 'redis', connectionStringEnv: 'ARKENIVA_CACHE_COMPARISON_URL' },
      },
      plugin: {
        id: 'cache-comparison',
        version: '1.0.0',
        capabilities: new Set(),
        dependencies: ['cache', 'database-redis'],
        init(context) {
          context.provide(key, {
            cache: context.require(COMPONENTS.cache),
            inspect: () => context.require(COMPONENTS.redis).native(),
            physical: (name) => prefix + name,
          });
        },
        async close(context) {
          await context
            .require(key)
            .inspect()
            .del(cacheKeys.map((name) => prefix + name));
        },
      },
      key,
    };
  },
  verify: verifyCache,
  workload: cacheWorkload,
  close: (service) => service.close(),
});
