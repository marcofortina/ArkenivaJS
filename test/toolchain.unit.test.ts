import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
test('EK-CORE-003 workspace uses strict ESM and private packages', () => {
  const pkg = JSON.parse(readFileSync('package.json', 'utf8')) as {
    private: boolean;
    type: string;
  };
  assert.equal(pkg.private, true);
  assert.equal(pkg.type, 'module');
});
