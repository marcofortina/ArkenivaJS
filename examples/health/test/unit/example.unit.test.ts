import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { Writable } from 'node:stream';
import { createHealthApplication } from '../../dist/main.js';

test('Health consumer serves local lifecycle probes through real HTTP and closes its listener', async () => {
  const reserve = createServer();
  await new Promise<void>((resolve) => reserve.listen(0, '127.0.0.1', resolve));
  const address = reserve.address();
  assert.ok(address && typeof address === 'object');
  await new Promise<void>((resolve) => reserve.close(() => resolve()));
  const app = await createHealthApplication({
    port: address.port,
    destination: new Writable({
      write(_chunk, _encoding, done) {
        done();
      },
    }),
  });
  const health = app.health;
  assert.equal((await health.ready()).status, 'not_ready');
  await app.start();
  try {
    for (const [path, status] of [
      ['/livez', 'live'],
      ['/readyz', 'ready'],
    ]) {
      const response: Response = await fetch('http://127.0.0.1:' + address.port + path);
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { status });
    }
  } finally {
    await app.stop();
  }
  assert.equal((await health.ready()).status, 'not_ready');
});

test('Health consumer rejects invalid ports and requires explicit authorization before connecting Redis', async () => {
  for (const port of [0, 65536, 1.5, NaN])
    await assert.rejects(createHealthApplication({ port }), { code: 'EK_CONFIG_INVALID' });
  const old = process.env.ARKENIVA_REDIS_DISPOSABLE;
  try {
    delete process.env.ARKENIVA_REDIS_DISPOSABLE;
    await assert.rejects(createHealthApplication({ redis: true }), { code: 'EK_CONFIG_INVALID' });
  } finally {
    if (old === undefined) delete process.env.ARKENIVA_REDIS_DISPOSABLE;
    else process.env.ARKENIVA_REDIS_DISPOSABLE = old;
  }
});
