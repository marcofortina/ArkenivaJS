import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, COMPONENTS } from '@arkenivajs/core';
import { cachePlugin } from '@arkenivajs/cache';
import { redisPortDouble } from '../fixtures/redis-port-double.js';

const service = { name: 'cache-contract', version: '1.0.0', environment: 'test' as const };

test('Cache facade stays frozen, inactive before start and closed after stop without owning its declared Redis port', async () => {
  const f = redisPortDouble(),
    options = { namespace: 'captured:', defaultTtlMs: 42 },
    plugin = cachePlugin(options);
  options.namespace = 'changed:';
  options.defaultTtlMs = 0;
  let nativeCloses = 0;
  const app = await createApplication({
    service,
    plugins: [
      plugin,
      {
        id: 'database-redis',
        version: '0.1.0',
        capabilities: new Set(['redis']),
        init(context) {
          context.provide(COMPONENTS.redis, f.redis);
        },
        close() {
          nativeCloses++;
        },
      },
    ],
  });
  const cache = app.cache!;
  assert.equal(Object.isFrozen(cache), true);
  await assert.rejects(cache.get('key'), { code: 'EK_LIFECYCLE_STATE' });
  await app.start();
  try {
    await cache.set('key', { name: 'Ada' });
    assert.equal(f.state.calls[0]!.key, 'captured:key');
    assert.equal(f.state.calls[0]!.options?.ttlMs, 42);
    assert.equal(nativeCloses, 0);
  } finally {
    await app.stop();
  }
  assert.equal(nativeCloses, 1);
  for (const call of [
    () => cache.get('key'),
    () => cache.set('key', {}),
    () => cache.delete('key'),
  ])
    await assert.rejects(call, { code: 'EK_RESOURCE_CLOSED' });
});

test('Cache invalid policy and missing dependencies reject before any native initialization', async () => {
  for (const options of [
    { namespace: null },
    { defaultTtlMs: 0 },
    { redisDependency: '' },
    { redisDependency: 42 },
    null,
  ])
    assert.throws(() => cachePlugin(options as never), { code: 'EK_CONFIG_INVALID' });
  await assert.rejects(createApplication({ service, plugins: [cachePlugin()] }), {
    code: 'EK_PLUGIN_DEPENDENCY',
  });
  const app = await createApplication({
    service,
    plugins: [
      cachePlugin(),
      {
        id: 'database-redis',
        version: '0.1.0',
        capabilities: new Set(['redis']),
        init() {},
        close() {},
      },
    ],
  });
  await assert.rejects(app.start());
  await app.stop();
});
