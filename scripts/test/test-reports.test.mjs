// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, writeFile, readFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { testReportArguments } from '../test-reports.mjs';

test('Native reporters retain passing, failing and coverage evidence with the correct process status', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-test-reporting-'));
  try {
    const source = join(directory, 'observed.mjs');
    const suite = join(directory, 'suite.test.mjs');
    await writeFile(source, 'export const observed = () => 7;\n');
    await writeFile(
      suite,
      "import {test} from 'node:test';import assert from 'node:assert/strict';import {observed} from './observed.mjs';test('Observed result',()=>assert.equal(observed(),7));\n",
    );
    const environment = { ...process.env };
    // The nested fixture must own a real runner rather than inherit the parent's child protocol.
    delete environment.NODE_TEST_CONTEXT;
    const run = (label, coverage) =>
      spawnSync(
        process.execPath,
        [
          '--test',
          ...(coverage
            ? ['--experimental-test-coverage', '--test-coverage-include=' + source]
            : []),
          ...testReportArguments(label, coverage, directory),
          suite,
        ],
        { encoding: 'utf8', timeout: 15000, env: environment },
      );
    const passing = run('passing', true);
    assert.equal(passing.status, 0, passing.stderr);
    assert.match(
      await readFile(join(directory, 'passing.junit.xml'), 'utf8'),
      /<testcase[^>]*name="Observed result"/,
    );
    assert.match(await readFile(join(directory, 'passing.lcov'), 'utf8'), /SF:.*observed\.mjs/);
    await writeFile(
      suite,
      "import {test} from 'node:test';test('Controlled failure',()=>{throw new Error('Expected fixture failure')});\n",
    );
    assert.equal(run('failing', false).status, 1);
    assert.match(await readFile(join(directory, 'failing.junit.xml'), 'utf8'), /<failure/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
test('Report labels cannot address another file and existing symlink destinations are rejected', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-test-report-safety-'));
  try {
    assert.throws(() => testReportArguments('../elsewhere', false, directory));
    const target = join(directory, 'target');
    await writeFile(target, 'Retain this content');
    await symlink(target, join(directory, 'linked.junit.xml'));
    assert.throws(() => testReportArguments('linked', false, directory));
    assert.equal(await readFile(target, 'utf8'), 'Retain this content');
    const previous = process.env.ARKENIVA_TEST_REPORT_DIRECTORY;
    try {
      delete process.env.ARKENIVA_TEST_REPORT_DIRECTORY;
      assert.deepEqual(testReportArguments('unused', false), []);
    } finally {
      if (previous !== undefined) process.env.ARKENIVA_TEST_REPORT_DIRECTORY = previous;
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
