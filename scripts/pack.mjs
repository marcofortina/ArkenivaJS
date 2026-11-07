// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, open, unlink } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { captureFile } from './file-capture.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const licenseHash = '0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0';

/** Supply the exact repository license without overwriting an existing package file. */
export async function withPackageLicense(repository, location, action) {
  const source = join(repository, 'LICENSE'),
    target = join(location, 'LICENSE');
  const { bytes, info } = await captureFile(source, 1024 * 1024, 'Unreviewed root license');
  assert.equal(
    createHash('sha256').update(bytes).digest('hex'),
    licenseHash,
    'Unreviewed root license',
  );
  let created;
  try {
    let file;
    try {
      file = await open(
        target,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        Number(info.mode & 0o777n),
      );
      created = await file.stat({ bigint: true });
      await file.writeFile(bytes);
      await file.chmod(Number(info.mode & 0o777n));
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    } finally {
      await file?.close();
    }
    const captured = await captureFile(
      target,
      1024 * 1024,
      'Package license must be a regular file and remain unchanged',
    );
    if (created)
      assert.ok(
        captured.info.dev === created.dev && captured.info.ino === created.ino,
        'Package license was replaced before packing',
      );
    assert.ok(captured.bytes.equals(bytes), 'Package license differs from the root license');
    return await action();
  } finally {
    if (created) {
      const current = await lstat(target, { bigint: true });
      assert.ok(
        current.isFile() && current.dev === created.dev && current.ino === created.ino,
        'Package license was replaced before cleanup',
      );
      await unlink(target);
    }
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
