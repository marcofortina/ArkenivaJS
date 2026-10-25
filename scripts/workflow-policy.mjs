import assert from 'node:assert/strict';
import { parse } from 'yaml';

/** Structural checks complement the required upstream review of every immutable action SHA. */
export function validateWorkflow(name, text) {
  const workflow = parse(text);
  assert.ok(workflow && typeof workflow === 'object', 'A workflow must be a mapping');
  assert.deepEqual(
    workflow.permissions,
    { contents: 'read' },
    'Workflow permissions must default to read-only contents',
  );
  assert.ok(workflow.on && typeof workflow.on === 'object', 'Workflow events must be explicit');
  const events = Object.keys(workflow.on);
  assert.ok(events.length > 0);
  for (const event of events)
    assert.ok(
      ['push', 'schedule', 'workflow_dispatch'].includes(event),
      'Unsupported or untrusted workflow event',
    );
  if (workflow.on.push !== undefined)
    assert.deepEqual(
      workflow.on.push,
      { branches: ['main'] },
      'Push workflows must target main without hidden path filters',
    );
  if (workflow.on.schedule !== undefined) {
    assert.ok(Array.isArray(workflow.on.schedule) && workflow.on.schedule.length > 0);
    for (const schedule of workflow.on.schedule)
      assert.ok(
        typeof schedule.cron === 'string' && schedule.cron.trim().split(/\s+/).length === 5,
        'A schedule requires an explicit five-field cron',
      );
  }
  assert.ok(workflow.jobs && typeof workflow.jobs === 'object');
  let actions = 0;
  for (const [jobName, job] of Object.entries(workflow.jobs)) {
    assert.ok(
      job && Array.isArray(job.steps) && job.steps.length > 0,
      'Jobs require explicit steps',
    );
    assert.ok(
      job['continue-on-error'] === undefined || job['continue-on-error'] === false,
      'Required jobs cannot suppress failures',
    );
    if (job.permissions !== undefined) {
      const permitted =
        name === 'security.yml' && jobName === 'codeql'
          ? { actions: 'read', contents: 'read', 'security-events': 'write' }
          : { contents: 'read' };
      assert.deepEqual(job.permissions, permitted, 'A job requests unapproved permissions');
    }
    if (!workflow.on.push)
      assert.equal(
        job.if,
        "github.ref == 'refs/heads/main'",
        'Manual and scheduled jobs must stay on main',
      );
    for (const step of job.steps) {
      assert.ok(
        step['continue-on-error'] === undefined || step['continue-on-error'] === false,
        'Required steps cannot suppress failures',
      );
      if (step.uses === undefined) continue;
      assert.match(
        step.uses,
        /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+(?:\/[a-zA-Z0-9_.-]+)*@[0-9a-f]{40}$/,
        'Actions require full immutable commit SHAs',
      );
      if (step.uses.startsWith('actions/checkout@'))
        assert.equal(
          step.with?.['persist-credentials'],
          false,
          'Checkout credentials must not persist',
        );
      actions++;
    }
  }
  return { jobs: Object.keys(workflow.jobs).length, actions };
}
