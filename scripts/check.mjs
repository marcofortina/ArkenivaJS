import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { validateWorkflow } from './workflow-policy.mjs';
const files = readdirSync('.github/workflows')
  .filter((name) => /\.ya?ml$/.test(name))
  .sort();
assert.ok(files.length > 0, 'At least one workflow is required');
let jobs = 0,
  actions = 0;
for (const name of files) {
  const result = validateWorkflow(name, readFileSync('.github/workflows/' + name, 'utf8'));
  jobs += result.jobs;
  actions += result.actions;
}
console.log(
  'Workflow policy passed: ' +
    files.length +
    ' workflows, ' +
    jobs +
    ' job definitions and ' +
    actions +
    ' immutable action references.',
);
