import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { runMessagingExample } from '../../dist/main.js';

test('Messaging guide executes actual Core NATS publication, correlation, handler error strategy and closure', async () => {
  const expected = { acknowledged: false, received: 1, correlated: true, handlerFailures: 1 };
  assert.deepEqual(await runMessagingExample(), expected);
  const result = await promisify(execFile)(process.execPath, ['dist/main.js'], { timeout: 15000 });
  assert.deepEqual(JSON.parse(result.stdout), expected);
  assert.equal(result.stderr, '');
});
