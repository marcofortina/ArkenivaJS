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
