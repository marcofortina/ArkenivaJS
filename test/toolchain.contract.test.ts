import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
test('ESM compiler contract enables strict data and exception checks', () => {
  const config = JSON.parse(readFileSync('tsconfig.base.json', 'utf8')) as {
    compilerOptions: Record<string, unknown>;
  };
  for (const key of [
    'strict',
    'noUncheckedIndexedAccess',
    'exactOptionalPropertyTypes',
    'useUnknownInCatchVariables',
  ])
    assert.equal(config.compilerOptions[key], true);
});
