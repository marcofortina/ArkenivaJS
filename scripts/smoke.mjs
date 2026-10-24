import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const root = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
assert.equal(root.private, true);
assert.equal(root.type, 'module');
console.log('Workspace ESM smoke passed');
const { KitError } = await import('../packages/core/dist/index.js');
assert.equal(
  new KitError({ code: 'EK_INTERNAL', message: 'private' }).toSafeJSON().code,
  'EK_INTERNAL',
);
console.log('Core error ESM smoke passed');
const { ConfigStore } = await import('../packages/core/dist/support.js');
const config = new ConfigStore(
  { count: 1 },
  {
    schema: {
      type: 'object',
      properties: { count: { type: 'integer' } },
      additionalProperties: false,
    },
    dynamicPaths: ['count'],
  },
);
await config.reload({ count: 2 });
assert.equal(config.require('count'), 2);
assert.ok(Object.isFrozen(config.snapshot()));
console.log('Configuration store smoke passed');
