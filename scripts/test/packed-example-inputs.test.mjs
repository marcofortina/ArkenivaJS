// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, stat, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import {
  selectTestFiles,
  snapshotReviewedPatches,
  resolvedPatches,
} from '../packed-example-inputs.mjs';

test('Packed verification selects the exact unit, integration or browser glob instead of a fixed suffix', () => {
  const names = ['import.test.js', 'server.integration.js', 'login.browser.test.js'];
  assert.deepEqual(selectTestFiles('dist-test/*.integration.js', names), [
    'dist-test/server.integration.js',
  ]);
  assert.deepEqual(selectTestFiles('dist-test/*.browser.test.js', names), [
    'dist-test/login.browser.test.js',
  ]);
  assert.throws(() => selectTestFiles('dist-test/*.integration.js', ['import.test.js']));
  assert.throws(() => selectTestFiles('../*.js', names));
  assert.deepEqual(
    selectTestFiles('dist-test/integration/*.test.js', ['wire.test.js', 'ignore.js']),
    ['dist-test/integration/wire.test.js'],
  );
  assert.deepEqual(selectTestFiles('dist-test/test/unit/*.test.js', ['unit.test.js']), [
    'dist-test/test/unit/unit.test.js',
  ]);
  assert.throws(() => selectTestFiles('dist-test/../*.js', names));
});
test('Independent pnpm graph selection preserves resolved native patches and omits absent test-only dependencies', () => {
  const patches = {
    'native@1.2.3': 'reviewed-compat/0.diff',
    'fixture-only@2.0.0': 'reviewed-compat/1.diff',
  };
  assert.deepEqual(
    resolvedPatches(patches, [
      { settings: {}, importers: {} },
      { packages: { 'native@1.2.3': {} } },
    ]),
    { 'native@1.2.3': 'reviewed-compat/0.diff' },
  );
});
test('External consumers receive only packaged exact-version diffs with identical reviewed source bytes', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-packed-inputs-'));
  try {
    const root = join(directory, 'source'),
      packageRoot = join(directory, 'archive'),
      destination = join(directory, 'consumer'),
      path = 'packages/native/compat/fidelity.diff',
      bytes = 'diff --git a/value.js b/value.js\n';
    await mkdir(join(root, 'packages/native/compat'), { recursive: true });
    await mkdir(join(packageRoot, 'package/compat'), { recursive: true });
    await mkdir(destination);
    await writeFile(join(root, path), bytes);
    await writeFile(join(packageRoot, 'package/compat/fidelity.diff'), bytes);
    const archive = join(directory, 'native.tgz');
    execFileSync('tar', ['-czf', archive, '-C', packageRoot, 'package']);
    const archives = new Map([['native', { archive, manifest: { files: ['dist', 'compat'] } }]]),
      patches = { 'native-sdk@1.2.3': path };
    const result = await snapshotReviewedPatches({
      patches,
      archives,
      root,
      directory: destination,
    });
    assert.equal(await readFile(join(destination, result['native-sdk@1.2.3']), 'utf8'), bytes);
    assert.equal((await stat(join(destination, result['native-sdk@1.2.3']))).mode & 0o777, 0o600);
    await writeFile(join(root, path), bytes + 'unreviewed mutation\n');
    const other = join(directory, 'other');
    await mkdir(other);
    await assert.rejects(
      snapshotReviewedPatches({ patches, archives, root, directory: other }),
      /differs/,
    );
    for (const invalid of [{ 'native-sdk@*': path }, { 'native-sdk@1.2.3': '../outside.diff' }]) {
      const invalidDirectory = await mkdtemp(join(directory, 'invalid-'));
      await assert.rejects(
        snapshotReviewedPatches({ patches: invalid, archives, root, directory: invalidDirectory }),
      );
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
