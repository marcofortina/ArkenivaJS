import test from 'node:test';
import assert from 'node:assert/strict';
import { runMongoDBExample } from '../../dist/main.js';

test('The MongoDB guide executes native BSON, exact counts, bounded aggregation and real session commit/rollback', async () => {
  const value = await runMongoDBExample();
  assert.match(value.id, /^[0-9a-f]{24}$/);
  assert.deepEqual(
    { ...value, id: 'opaque-id' },
    {
      id: 'opaque-id',
      name: 'Ada',
      balance: '1234567890.123456789',
      exact: '9007199254740993',
      changed: 1,
      unchanged: 0,
      committed: true,
      rolledBack: true,
    },
  );
});
