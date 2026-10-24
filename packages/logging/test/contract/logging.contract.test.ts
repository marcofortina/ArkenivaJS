import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import { createLogger } from '@arkenivajs/logging';
import type { Logger } from '@arkenivajs/logging';

test('Logger public methods preserve synchronous emission and asynchronous flush', async () => {
  const managed = createLogger({
    service: { name: 'log-contract', version: '1.0.0', environment: 'test' },
    destination: new Writable({
      write(_chunk, _encoding, callback) {
        callback();
      },
    }),
  });
  const logger: Logger = managed;
  const result: void = logger.info('message');
  assert.equal(result, undefined);
  await logger.flush({ timeoutMs: 100 });
  await managed.close();
});
