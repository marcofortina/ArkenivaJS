import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import fc from 'fast-check';
import { createLogger } from '@arkenivajs/logging';

test('EK-LOG-001 random secret values never appear in nested credential fields', async () => {
  await fc.assert(
    fc.asyncProperty(fc.string({ minLength: 1 }), async (secret) => {
      const lines: string[] = [];
      const destination = new Writable({
        write(chunk, _encoding, callback) {
          lines.push(String(chunk));
          callback();
        },
      });
      const logger = createLogger({
        service: { name: 'property-log', version: '1.0.0', environment: 'test' },
        destination,
      });
      logger.info('redaction test', {
        nested: { password: secret, token: secret, authorization: secret, clientSecret: secret },
      });
      await logger.flush();
      const value = JSON.parse(lines[0]!);
      assert.deepEqual(Object.values(value.nested), [
        '[REDACTED]',
        '[REDACTED]',
        '[REDACTED]',
        '[REDACTED]',
      ]);
      await logger.close();
    }),
    { seed: 2411, numRuns: 300 },
  );
});
