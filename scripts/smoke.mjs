import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const root = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
assert.equal(root.private, true);
assert.equal(root.type, 'module');
console.log('Workspace ESM smoke passed');
