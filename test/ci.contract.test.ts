import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
test('CI uses immutable official Actions and read-only permissions', () => {
  const workflow = readFileSync('.github/workflows/ci.yml', 'utf8');
  const pins = [...workflow.matchAll(/uses: (actions\/[a-z-]+)@([a-f0-9]+)/g)];
  const uniqueActions = new Set(pins.map((pin) => pin[1]));
  assert.deepEqual([...uniqueActions].sort(), ['actions/checkout', 'actions/setup-node']);
  for (const name of uniqueActions) {
    assert.equal(new Set(pins.filter((pin) => pin[1] === name).map((pin) => pin[2])).size, 1);
  }
  for (const pin of pins) assert.equal(pin[2]?.length, 40);
  assert.ok(workflow.includes('contents: read'));
  assert.ok(!workflow.includes('pull_request_target'));
  assert.ok(!workflow.includes('continue-on-error'));
});
