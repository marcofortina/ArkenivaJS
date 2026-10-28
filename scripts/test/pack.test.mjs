// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { withPackageLicense } from '../pack.mjs';

test('Package licensing preserves exact bytes, existing files and cleanup after failed packing', async () => {
  const root = await mkdtemp(join(tmpdir(), 'arkenivajs-pack-license-'));
  const location = join(root, 'fixture'),
    target = join(location, 'LICENSE');
  try {
    await mkdir(location);
    await copyFile(new URL('../../LICENSE', import.meta.url), join(root, 'LICENSE'));
    const expected = await readFile(join(root, 'LICENSE'));
    const absent = () => assert.rejects(lstat(target), { code: 'ENOENT' });
    assert.equal(
      await withPackageLicense(root, location, async () => {
        assert.deepEqual(await readFile(target), expected);
        return 42;
      }),
      42,
    );
    await absent();
    await assert.rejects(
      withPackageLicense(root, location, () => {
        throw new Error('Packing failed');
      }),
      /Packing failed/,
    );
    await absent();
    await writeFile(target, expected);
    await withPackageLicense(root, location, () => {});
    assert.deepEqual(await readFile(target), expected);
    await writeFile(target, 'Different license');
    await assert.rejects(
      withPackageLicense(root, location, () => assert.fail('Unexpected pack')),
      /differs/,
    );
    assert.equal(await readFile(target, 'utf8'), 'Different license');
    await rm(target);
    await symlink(join(root, 'LICENSE'), target);
    await assert.rejects(
      withPackageLicense(root, location, () => assert.fail('Unexpected pack')),
      /regular file/,
    );
    assert.ok((await lstat(target)).isSymbolicLink());
    await rm(target);
    await writeFile(join(root, 'LICENSE'), 'Unreviewed text');
    await assert.rejects(
      withPackageLicense(root, location, () => assert.fail('Unexpected pack')),
      /Unreviewed/,
    );
    await absent();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
