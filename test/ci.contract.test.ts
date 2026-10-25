// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
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
