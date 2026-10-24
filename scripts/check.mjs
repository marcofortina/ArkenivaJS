import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
const workflow = readFileSync('.github/workflows/ci.yml', 'utf8');
for (const match of workflow.matchAll(/uses: ([^\s]+)@([^\s]+)/g)) {
  assert.match(match[2], /^[0-9a-f]{40}$/);
}
assert.deepEqual(parse(workflow).on, { push: { branches: ['main'] } });
assert.ok(workflow.includes('contents: read'));
console.log('Main-only triggers, action pins and permissions checks passed');
