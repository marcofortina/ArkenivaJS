import test from 'node:test';
import assert from 'node:assert/strict';
import { runMariadbOrdersExample } from '../../dist/main.js';

test('The built MariaDB consumer verifies exact values, real duplicate rejection and rollback against disposable InnoDB', async () => {
  assert.deepEqual(await runMariadbOrdersExample(), {
    rows: [{ id: '9007199254740993', total: '5.25' }],
    duplicateRejected: true,
    rollbackVerified: true,
  });
});
