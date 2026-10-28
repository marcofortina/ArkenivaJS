// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, writeFile, chmod, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { registry } from '../http-fixture.js';
import { runRegistryCli } from '../../dist/registry-cli.js';

const binary = fileURLToPath(new URL('../../dist/registry-bin.js', import.meta.url));
function run(args: readonly string[]) {
  return new Promise<{ code: number; stdout: string; stderr: string }>((resolve) => {
    execFile(
      process.execPath,
      [binary, ...args],
      { timeout: 5000, maxBuffer: 16384 },
      (error, stdout, stderr) =>
        resolve({
          code: typeof error?.code === 'number' ? error.code : error ? -1 : 0,
          stdout,
          stderr,
        }),
    );
  });
}
test('The actual registry executable validates a private deployment file and returns only bounded metadata', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-registry-cli-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = join(directory, 'registry.json');
  await writeFile(file, JSON.stringify(registry()), { mode: 0o600 });
  const result = await run(['validate', '--file', file, '--environment', 'test']);
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), {
    valid: true,
    schemaVersion: '1.1.0',
    revision: 'stable-blue',
    activationGeneration: 1,
    operations: 2,
    bindings: 4,
  });
  assert.equal(result.stderr, '');
  assert.doesNotMatch(result.stdout, /north|south|handler|file|schemas/);
  const deniedRoot = await run([
    'validate',
    '--file',
    file,
    '--environment',
    'test',
    '--public-root',
    directory,
  ]);
  assert.equal(deniedRoot.code, 1);
  assert.equal(deniedRoot.stderr, 'Tenant registry validation failed\n');
  await chmod(file, 0o644);
  assert.equal((await run(['validate', '--file', file, '--environment', 'test'])).code, 1);
});

test('Malformed commands, unsafe files and invalid registry contents cannot execute or expose deployment material', async (t) => {
  for (const args of [
    [],
    ['validate'],
    ['run', '--file', '/private'],
    ['validate', '--file', 'relative'],
    ['validate', '--file', '/private', '--file', '/other'],
    ['validate', '--file', '/private', '--environment', 'unknown'],
    ['validate', '--file', '/private', '--max-bytes', '0'],
    ['validate', '--file', '/private', '--max-bytes', '134217729'],
    ['validate', '--file', '/private', '--unknown', 'private'],
  ]) {
    const result = await run(args);
    assert.equal(result.code, 2);
    assert.match(result.stderr, /^Usage:/);
    assert.equal(result.stdout, '');
  }
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-registry-cli-invalid-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = join(directory, 'registry.json'),
    link = join(directory, 'linked.json');
  await writeFile(file, '{"private-deployment-marker":true}', { mode: 0o600 });
  await symlink(file, link);
  for (const path of [file, link, directory, join(directory, 'missing')]) {
    const result = await run(['validate', '--file', path, '--environment', 'test']);
    assert.equal(result.code, 1);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, 'Tenant registry validation failed\n');
  }
  await writeFile(file, JSON.stringify(registry()));
  const output: string[] = [];
  assert.equal(
    await runRegistryCli(
      ['validate', '--file', file, '--environment', 'test'],
      { stdout: (value) => output.push(value), stderr: (value) => output.push(value) },
      { signal: AbortSignal.abort() },
    ),
    1,
  );
  assert.deepEqual(output, ['Tenant registry validation failed\n']);
  assert.equal((await run(['--help'])).code, 0);
});
