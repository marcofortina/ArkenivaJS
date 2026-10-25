import test from 'node:test';
import assert from 'node:assert/strict';
import { runCacheExample } from '../../dist/main.js';

test('Cache guide executes checked JSON, acknowledged writes, actual deletion outcomes and native millisecond expiration', async () => {
  assert.deepEqual(await runCacheExample(), {
    id: 'customer-42',
    name: 'Ada',
    removed: true,
    removedAgain: false,
    expired: true,
  });
});
