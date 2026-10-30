// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execute = promisify(execFile);
const root = fileURLToPath(new URL('../../', import.meta.url));
const forbidden = new Set([
  '@arkenivajs/graphql',
  'graphql',
  'mercurius',
  'graphiql',
  'graphql-ws',
  'react',
  'react-dom',
]);

test('Core and REST production dependency closures contain no optional GraphQL engine or frontend', async () => {
  const { stdout } = await execute(
    'pnpm',
    [
      'list',
      '--prod',
      '--depth',
      'Infinity',
      '--json',
      '--filter',
      '@arkenivajs/core',
      '--filter',
      '@arkenivajs/api',
    ],
    { cwd: root, timeout: 15000, maxBuffer: 4194304 },
  );
  const projects = JSON.parse(stdout);
  assert.deepEqual(projects.map((project) => project.name).sort(), [
    '@arkenivajs/api',
    '@arkenivajs/core',
  ]);
  let dependencies = 0;
  const visit = (node) => {
    for (const kind of ['dependencies', 'optionalDependencies'])
      for (const [name, dependency] of Object.entries(node[kind] ?? {})) {
        assert.equal(forbidden.has(name), false, 'Unexpected production dependency: ' + name);
        dependencies++;
        visit(dependency);
      }
  };
  for (const project of projects) visit(project);
  assert.ok(
    dependencies > 10,
    'The actual installed transitive dependency graph must be traversed',
  );
});

test(
  'A real REST-only application serves HTTP and closes while GraphQL imports are actively forbidden',
  { timeout: 15000 },
  async () => {
    const { stdout } = await execute(
      process.execPath,
      [fileURLToPath(new URL('./rest-optionality-worker.mjs', import.meta.url))],
      { cwd: root, timeout: 12000, maxBuffer: 1048576 },
    );
    assert.deepEqual(JSON.parse(stdout), {
      restStatus: 200,
      absentGraphqlStatus: 404,
      optionalImports: 0,
      activeNegativeControls: 2,
      closed: true,
    });
  },
);
