// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
test('SMTP integration verifies actual TLS, native recipient outcomes and packed consumers on each Node line', () => {
  const workflow = parse(readFileSync('.github/workflows/ci.yml', 'utf8')),
    job = workflow.jobs['mail-integration'];
  assert.deepEqual(job.strategy.matrix.node, ['22.23.4', '24.22.1', '26.12.1']);
  assert.equal(job.strategy['fail-fast'], false);
  const commands = (job.steps as readonly { run?: string }[]).flatMap((step) =>
    step.run ? [step.run] : [],
  );
  for (const command of [
    'pnpm --filter @arkenivajs/mail test:integration',
    'pnpm --filter @arkenivajs/example-mail test',
    'pnpm test:packed:examples --example mail',
  ])
    assert.ok(commands.includes(command));
  assert.ok(!JSON.stringify(job).includes('NODE_TLS_REJECT_UNAUTHORIZED'));
  assert.ok(!JSON.stringify(job).includes('continue-on-error'));
});
test('Webhook integration verifies raw signatures, TLS and packed consumers on each Node line', () => {
  const workflow = parse(readFileSync('.github/workflows/ci.yml', 'utf8')),
    job = workflow.jobs['webhooks-integration'];
  assert.deepEqual(job.strategy.matrix.node, ['22.23.4', '24.22.1', '26.12.1']);
  assert.equal(job.strategy['fail-fast'], false);
  const commands = (job.steps as readonly { run?: string }[]).flatMap((step) =>
    step.run ? [step.run] : [],
  );
  for (const command of [
    'pnpm --filter @arkenivajs/webhooks test:integration',
    'pnpm --filter @arkenivajs/example-webhooks test',
    'pnpm test:packed:examples --example webhooks',
  ])
    assert.ok(commands.includes(command));
  assert.ok(!JSON.stringify(job).includes('NODE_TLS_REJECT_UNAUTHORIZED'));
  assert.ok(!JSON.stringify(job).includes('continue-on-error'));
});
test('Multipart integration verifies native HTTP, HTTPS, HTTP2 and packed consumers on each Node line', () => {
  const workflow = parse(readFileSync('.github/workflows/ci.yml', 'utf8')),
    job = workflow.jobs['upload-integration'];
  assert.deepEqual(job.strategy.matrix.node, ['22.23.4', '24.22.1', '26.12.1']);
  assert.equal(job.strategy['fail-fast'], false);
  const commands = (job.steps as readonly { run?: string }[]).flatMap((step) =>
    step.run ? [step.run] : [],
  );
  for (const command of [
    'pnpm --filter @arkenivajs/upload test:integration',
    'pnpm --filter @arkenivajs/example-upload test',
    'pnpm test:packed:examples --example upload',
  ])
    assert.ok(commands.includes(command));
  assert.ok(!JSON.stringify(job).includes('NODE_TLS_REJECT_UNAUTHORIZED'));
  assert.ok(!JSON.stringify(job).includes('continue-on-error'));
});
test('CI runs only on main pushes with immutable official Actions and read-only permissions', () => {
  const workflow = readFileSync('.github/workflows/ci.yml', 'utf8');
  const pins = [...workflow.matchAll(/uses: (actions\/[a-z-]+)@([a-f0-9]+)/g)];
  const uniqueActions = new Set(pins.map((pin) => pin[1]));
  assert.deepEqual([...uniqueActions].sort(), [
    'actions/checkout',
    'actions/setup-node',
    'actions/upload-artifact',
  ]);
  for (const name of uniqueActions) {
    assert.equal(new Set(pins.filter((pin) => pin[1] === name).map((pin) => pin[2])).size, 1);
  }
  for (const pin of pins) assert.equal(pin[2]?.length, 40);
  assert.ok(workflow.includes('contents: read'));
  assert.deepEqual(parse(workflow).on, { push: { branches: ['main'] } });
  assert.ok(!workflow.includes('continue-on-error'));
});

test('PostgreSQL compatibility covers both reviewed servers on every supported Node line', () => {
  const workflow = parse(readFileSync('.github/workflows/ci.yml', 'utf8'));
  const job = workflow.jobs['postgres-integration'];
  assert.deepEqual(job.strategy.matrix, {
    node: ['22.23.4', '24.22.1', '26.12.1'],
    postgres: ['17', '18'],
  });
  assert.equal(job.strategy['fail-fast'], false);
  const commands = (job.steps as readonly { run?: string }[]).flatMap((step) =>
    step.run ? [step.run] : [],
  );
  const guards = commands.indexOf(
    'python3 packages/database-postgres/test/fixtures/test_prepare.py',
  );
  const preparation = commands.findIndex((command) =>
    command.startsWith('python3 packages/database-postgres/test/fixtures/prepare.py '),
  );
  assert.ok(guards >= 0 && preparation > guards);
  assert.ok(commands[preparation]?.includes('--server-major "${{ matrix.postgres }}"'));
  for (const gate of [
    'pnpm coverage:postgres',
    'pnpm --filter @arkenivajs/benchmark-foundation test:integration',
    'pnpm --filter @arkenivajs/example-postgres test:integration',
    'pnpm test:packed:examples --integration postgres',
    'pnpm --filter @arkenivajs/example-postgres test:browser',
    'pnpm test:packed:examples --browser postgres',
  ])
    assert.ok(commands.includes(gate), 'Every PostgreSQL/Node pair must run ' + gate);
  const browser = job.steps.find(
    (step: { run?: string }) =>
      step.run === 'pnpm --filter @arkenivajs/example-postgres test:browser',
  );
  assert.equal(browser.env.ARKENIVA_WEBAUTHN_BROWSER_DISPOSABLE, '1');
  const fixture = parse(
    readFileSync('examples/postgres/test/fixtures/browser/compose.yaml', 'utf8'),
  ).services.chromium;
  assert.match(
    fixture.image,
    /^mcr\.microsoft\.com\/playwright:v1\.64\.0-noble@sha256:[a-f0-9]{64}$/,
  );
  assert.equal(fixture.read_only, true);
  assert.equal(fixture.network_mode, 'host');
  assert.ok(fixture.command.includes('--remote-debugging-address=127.0.0.1'));
});

test('Optional standard APIs retain explicit Node/package coverage and cannot bypass public contract gates', () => {
  const workflow = parse(readFileSync('.github/workflows/ci.yml', 'utf8'));
  const job = workflow.jobs['standard-apis-unit'];
  assert.deepEqual(job.strategy.matrix, {
    node: ['22.23.4', '24.22.1', '26.12.1'],
    package: [
      'cli',
      'data-barcodes',
      'data-compression',
      'data-csv',
      'data-identifiers',
      'data-time',
      'data-validation',
      'dns',
      'mail',
      'security-apikey',
      'security-crypto',
      'security-http',
      'security-mtls',
      'security-password',
      'security-sessions',
      'security-x509',
      'socket',
      'upload',
      'webhooks',
    ],
  });
  assert.equal(job.strategy['fail-fast'], false);
  assert.ok(job['timeout-minutes'] <= 10);
  const commands = (job.steps as readonly { run?: string }[]).flatMap((step) =>
    step.run ? [step.run] : [],
  );
  for (const gate of ['build', 'typecheck', 'lint', 'test'])
    assert.ok(
      commands.some((command) => command.includes('matrix.package') && command.includes(gate)),
    );
  assert.ok(commands.includes('pnpm install --frozen-lockfile'));
  const checks = (workflow.jobs.checks.steps as readonly { run?: string }[]).flatMap((step) =>
    step.run ? [step.run] : [],
  );
  assert.ok(checks.includes('pnpm verify'));
  assert.ok(checks.includes('pnpm --filter @arkenivajs/benchmark-foundation test'));
});

test('Performance campaigns remain explicit manual main-only work while functional gates stay automatic', () => {
  const functional = parse(readFileSync('.github/workflows/ci.yml', 'utf8'));
  const performance = parse(readFileSync('.github/workflows/performance.yml', 'utf8'));
  assert.deepEqual(Object.keys(performance.on), ['workflow_dispatch']);
  assert.deepEqual(performance.jobs['native-security'].strategy.matrix, {
    node: ['22.23.4', '24.22.1', '26.12.1'],
  });
  assert.deepEqual(performance.jobs['durable-identity'].strategy.matrix, {
    node: ['22.23.4', '24.22.1', '26.12.1'],
    postgres: ['17', '18'],
  });
  const commands = (workflow: typeof performance) =>
    Object.values(workflow.jobs).flatMap((job: unknown) =>
      (job as { steps: readonly { run?: string }[] }).steps.flatMap((step) =>
        step.run ? [step.run] : [],
      ),
    );
  const automatic = commands(functional),
    manual = commands(performance);
  assert.ok(automatic.includes('pnpm verify'));
  assert.ok(automatic.includes('pnpm --filter @arkenivajs/benchmark-foundation test'));
  assert.ok(automatic.includes('pnpm --filter @arkenivajs/example-postgres test:integration'));
  for (const tool of ['crypto', 'x509', 'mfa']) {
    assert.ok(
      manual.some((command) => command.includes('benchmark-foundation ' + tool + ' --smoke')),
    );
    assert.ok(
      !automatic.some((command) => command.includes('benchmark-foundation ' + tool + ' --smoke')),
    );
  }
  for (const job of Object.values(performance.jobs))
    assert.equal((job as { if: string }).if, "github.ref == 'refs/heads/main'");
});
