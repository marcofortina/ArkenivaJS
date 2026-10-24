import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createConfig } from '@arkenivajs/config';
import type { ConfigService } from '@arkenivajs/config';
test('ConfigService preserves typed top-level access and immutable views', async () => {
  const config: ConfigService<{ count: number }> = await createConfig({
    workspace: process.cwd(),
    schema: {
      type: 'object',
      properties: { count: { type: 'integer' } },
      additionalProperties: false,
    },
    runtime: { count: 1 },
    environment: {},
  });
  const count: number = config.require('count');
  assert.equal(count, 1);
  assert.equal(config.snapshot().count, count);
});
