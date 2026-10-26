// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { stringify } from 'yaml';
import { validateWorkflow } from '../workflow-policy.mjs';

const fixture = () => ({
  on: { push: { branches: ['main'] } },
  permissions: { contents: 'read' },
  jobs: {
    checks: {
      'runs-on': 'ubuntu-latest',
      steps: [
        { uses: 'actions/checkout@' + 'a'.repeat(40), with: { 'persist-credentials': false } },
        { run: 'node scripts/smoke.mjs' },
      ],
    },
  },
});

test('Job environment rejects unavailable runner contexts while step environment may resolve them', () => {
  for (const expression of [
    '${{ runner.temp }}',
    "${{ runner['temp'] }}",
    '${{ steps.prepare.outputs.directory }}',
    '${{ env.ROOT }}',
    '${{ job.status }}',
  ]) {
    const value = fixture();
    value.jobs.checks.env = { REPORT_DIRECTORY: expression };
    assert.throws(
      () => validateWorkflow('ci.yml', stringify(value)),
      /Job environment cannot reference/,
    );
  }
  const value = fixture();
  value.jobs.checks.steps[0].env = { REPORT_DIRECTORY: '${{ runner.temp }}' };
  assert.doesNotThrow(() => validateWorkflow('ci.yml', stringify(value)));
  value.jobs.checks.env = { NODE_VERSION: '${{ matrix.node }}' };
  assert.doesNotThrow(() => validateWorkflow('ci.yml', stringify(value)));
});
test('Workflow policy rejects untrusted triggers, mutable actions and hidden failure suppression', () => {
  assert.deepEqual(validateWorkflow('ci.yml', stringify(fixture())), { jobs: 1, actions: 1 });
  const changes = [
    (value) => {
      value.on = { pull_request: {} };
    },
    (value) => {
      value.on.push.branches = ['development'];
    },
    (value) => {
      value.on.push.paths = ['docs/**'];
    },
    (value) => {
      value.permissions.contents = 'write';
    },
    (value) => {
      value.jobs.checks.permissions = { contents: 'write' };
    },
    (value) => {
      value.jobs.checks['continue-on-error'] = true;
    },
    (value) => {
      value.jobs.checks.steps[0].uses = 'actions/checkout@main';
    },
    (value) => {
      value.jobs.checks.steps[0].with['persist-credentials'] = true;
    },
    (value) => {
      value.jobs.checks.steps[1]['continue-on-error'] = true;
    },
  ];
  for (const change of changes) {
    const value = fixture();
    change(value);
    assert.throws(() => validateWorkflow('ci.yml', stringify(value)));
  }
});
test('Scheduled/manual checks stay on main and only the CodeQL job may upload security events', () => {
  const value = fixture();
  value.on = { workflow_dispatch: null, schedule: [{ cron: '19 4 * * 1' }] };
  assert.throws(() => validateWorkflow('compatibility.yml', stringify(value)));
  value.jobs.checks.if = "github.ref == 'refs/heads/main'";
  assert.doesNotThrow(() => validateWorkflow('compatibility.yml', stringify(value)));
  value.jobs.codeql = value.jobs.checks;
  delete value.jobs.checks;
  value.jobs.codeql.permissions = { actions: 'read', contents: 'read', 'security-events': 'write' };
  assert.doesNotThrow(() => validateWorkflow('security.yml', stringify(value)));
  assert.throws(() => validateWorkflow('compatibility.yml', stringify(value)));
});
