import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { Writable } from 'node:stream';
import { createHealthApplication } from '../../dist/main.js';

test('Health consumer confirms actual authenticated Redis before exposing ready HTTP', async () => {
  assert.equal(process.env.ARKENIVA_REDIS_DISPOSABLE, '1');
  assert.ok(process.env.ARKENIVA_REDIS_URL);
  const reserve = createServer();
  await new Promise<void>((resolve) => reserve.listen(0, '127.0.0.1', resolve));
  const address = reserve.address();
  assert.ok(address && typeof address === 'object');
  await new Promise<void>((resolve) => reserve.close(() => resolve()));
  const app = await createHealthApplication({
    port: address.port,
    redis: true,
    destination: new Writable({
      write(_chunk, _encoding, done) {
        done();
      },
    }),
  });
  await app.start();
  try {
    assert.deepEqual(await app.health.ready(), { status: 'ready', failing: [] });
    const response = await fetch('http://127.0.0.1:' + address.port + '/readyz');
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { status: 'ready' });
  } finally {
    await app.stop();
  }
});
