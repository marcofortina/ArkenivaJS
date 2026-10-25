import test from 'node:test';
import assert from 'node:assert/strict';
import { runRedisCacheExample } from '../../dist/main.js';

test('The Redis cache guide executes real NX, eventual TTL, counters and exact deletion with owned-key cleanup', async () => {
  assert.deepEqual(await runRedisCacheExample(), {
    firstAccepted: true,
    secondAccepted: false,
    order: { id: '42', total: '5.25' },
    counter: 3,
    expired: true,
    deleted: 2,
  });
});
