// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, stat, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

for (const scenario of ['stable', 'replacement', 'mtime', 'ctime', 'lock'] as const)
  test(`Project operations preserve uint64 file ownership and nanosecond changes: ${scenario}`, async () => {
    const cwd = await mkdtemp(join(tmpdir(), 'arkeniva-cli-identity-')),
      manifest = join(cwd, 'package.json'),
      original = '{"name":"trusted","type":"module","dependencies":{"@arkenivajs/core":"0.1.0"}}\n',
      foreign = original.replace('trusted', 'foreign');
    try {
      assert.equal(Number(2n ** 53n), Number(2n ** 53n + 1n));
      await writeFile(manifest, original, { mode: 0o640 });
      const { stdout } = await promisify(execFile)(
        process.execPath,
        [new URL('../fixtures/file-identity-worker.js', import.meta.url).pathname, scenario],
        { cwd, timeout: 5000, maxBuffer: 65536 },
      );
      const result = JSON.parse(stdout) as {
        accepted: boolean;
        replaced: boolean;
        bigintCaptures: number;
        code?: string;
      };
      assert.equal(result.accepted, scenario === 'stable' || scenario === 'lock');
      if (scenario === 'lock') {
        assert.equal(
          await readFile(join(cwd, '.wide-service.arkenivajs.lock'), 'utf8'),
          'foreign lock',
        );
        assert.equal(result.replaced, true);
      } else if (scenario === 'stable') {
        assert.equal(
          JSON.parse(await readFile(manifest, 'utf8')).dependencies['@arkenivajs/dns'],
          '0.1.0',
        );
        assert.equal((await stat(manifest)).mode & 0o777, 0o640);
      } else {
        assert.equal(result.code, 'EK_CONFIG_INVALID');
        assert.equal(result.replaced, true);
        assert.equal(await readFile(manifest, 'utf8'), foreign);
      }
      assert.equal(
        (await readdir(cwd)).some((name) => name.endsWith('.tmp')),
        false,
      );
    } finally {
      await rm(cwd, { recursive: true, force: true });
    }
  });
