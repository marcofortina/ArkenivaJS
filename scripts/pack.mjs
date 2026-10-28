// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { copyFile, lstat, readFile, unlink } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = fileURLToPath(new URL('../', import.meta.url));
const licenseHash = '0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0';

/** Supply the exact repository license without overwriting an existing package file. */
export async function withPackageLicense(repository, location, action) {
  const source = join(repository, 'LICENSE'),
    target = join(location, 'LICENSE');
  const bytes = await readFile(source);
  assert.equal(
    createHash('sha256').update(bytes).digest('hex'),
    licenseHash,
    'Unreviewed root license',
  );
  let created = false;
  try {
    try {
      await copyFile(source, target, constants.COPYFILE_EXCL);
      created = true;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
    assert.ok((await lstat(target)).isFile(), 'Package license must be a regular file');
    assert.deepEqual(
      await readFile(target),
      bytes,
      'Package license differs from the root license',
    );
    return await action();
  } finally {
    if (created) await unlink(target);
  }
}

export async function packPackage(location, destination) {
  assert.equal(dirname(resolve(location)), join(root, 'packages'), 'Pack only framework packages');
  return withPackageLicense(root, location, () => {
    const result = spawnSync(
      'pnpm',
      ['pack', '--ignore-scripts', '--pack-destination', resolve(destination)],
      {
        cwd: location,
        stdio: 'inherit',
        timeout: 180000,
      },
    );
    if (result.error) throw result.error;
    assert.equal(result.status, 0, 'Framework package creation failed');
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert.equal(process.argv.length, 4, 'Use node scripts/pack.mjs PACKAGE_DIRECTORY DESTINATION');
  await packPackage(resolve(process.argv[2]), resolve(process.argv[3]));
}
