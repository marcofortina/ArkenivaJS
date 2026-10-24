import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const workflow = readFileSync('.github/workflows/ci.yml', 'utf8');
for (const match of workflow.matchAll(/uses: ([^\s]+)@([^\s]+)/g)) {
  assert.match(match[2], /^[0-9a-f]{40}$/);
}
assert.ok(!workflow.includes('pull_request_target'));
assert.ok(workflow.includes('contents: read'));
console.log('Action pin and permissions checks passed');
