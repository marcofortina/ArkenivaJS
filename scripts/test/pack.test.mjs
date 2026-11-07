// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import {
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
  rename,
} from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { withPackageLicense } from '../pack.mjs';
import { captureFile } from '../file-capture.mjs';

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

test('Package licensing rejects a same-byte regular replacement before reading or packing it', async (context) => {
  const root = await mkdtemp(join(tmpdir(), 'arkenivajs-license-replacement-')),
    location = join(root, 'fixture'),
    target = join(location, 'LICENSE'),
    replacement = join(root, 'replacement');
  await mkdir(location);
  await copyFile(new URL('../../LICENSE', import.meta.url), join(root, 'LICENSE'));
  const bytes = await readFile(join(root, 'LICENSE'));
  await writeFile(target, bytes);
  await writeFile(replacement, bytes);
  assert.notEqual((await lstat(target)).ino, (await lstat(replacement)).ino);
  const originalStat = fs.lstat,
    originalRead = fs.readFile,
    originalOpen = fs.open,
    descriptors = [];
  let replaced = false,
    reads = 0,
    descriptorReads = 0,
    actions = 0;
  context.mock.method(fs, 'lstat', async (path, options) => {
    const value = await originalStat(path, options);
    if (path === target && !replaced) {
      replaced = true;
      await rename(replacement, target);
    }
    return value;
  });
  context.mock.method(fs, 'readFile', async (path, options) => {
    if (path === target) reads++;
    return originalRead(path, options);
  });
  context.mock.method(fs, 'open', async (path, flags, mode) => {
    const file = await originalOpen(path, flags, mode);
    descriptors.push(file);
    if (path === target) {
      const read = file.read;
      context.mock.method(file, 'read', function (...args) {
        descriptorReads++;
        return Reflect.apply(read, this, args);
      });
    }
    return file;
  });
  syncBuiltinESMExports();
  try {
    await assert.rejects(
      withPackageLicense(root, location, () => {
        actions++;
      }),
      /unchanged/,
    );
    assert.equal(replaced, true);
    assert.equal(reads, 0);
    assert.equal(descriptorReads, 0);
    assert.equal(actions, 0);
    assert.ok(descriptors.length > 0);
    assert.ok(descriptors.every((file) => file.fd === -1));
    assert.deepEqual(await originalRead(target), bytes);
  } finally {
    context.diagnostic(JSON.stringify({ replaced, reads, descriptorReads, actions }));
    context.mock.restoreAll();
    syncBuiltinESMExports();
    await rm(root, { recursive: true, force: true });
  }
});

test('Package licensing preserves source permissions under a restrictive creation mask', async () => {
  const root = await mkdtemp(join(tmpdir(), 'arkenivajs-license-mode-')),
    location = join(root, 'fixture'),
    source = join(root, 'LICENSE'),
    target = join(location, 'LICENSE');
  await mkdir(location);
  await copyFile(new URL('../../LICENSE', import.meta.url), source);
  await fs.chmod(source, 0o664);
  const mask = process.umask(0o077);
  try {
    await withPackageLicense(root, location, async () => {
      assert.equal((await lstat(target)).mode & 0o777, 0o664);
      assert.deepEqual(await readFile(target), await readFile(source));
    });
    assert.equal((await lstat(source)).mode & 0o777, 0o664);
    await assert.rejects(lstat(target), { code: 'ENOENT' });
  } finally {
    process.umask(mask);
    await rm(root, { recursive: true, force: true });
  }
});

test('Package cleanup preserves a foreign replacement after the packing action', async () => {
  const root = await mkdtemp(join(tmpdir(), 'arkenivajs-license-cleanup-')),
    location = join(root, 'fixture'),
    target = join(location, 'LICENSE'),
    foreign = join(root, 'foreign');
  try {
    await mkdir(location);
    await copyFile(new URL('../../LICENSE', import.meta.url), join(root, 'LICENSE'));
    await writeFile(foreign, 'foreign replacement', { mode: 0o600 });
    const identity = await lstat(foreign);
    await assert.rejects(
      withPackageLicense(root, location, () => rename(foreign, target)),
      /replaced before cleanup/,
    );
    assert.equal((await lstat(target)).ino, identity.ino);
    assert.equal(await readFile(target, 'utf8'), 'foreign replacement');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

for (const change of ['growth', 'metadata'])
  test(`Build input capture rejects ${change} during bounded reads and closes its descriptor`, async (context) => {
    const root = await mkdtemp(join(tmpdir(), 'arkenivajs-file-capture-')),
      path = join(root, 'input'),
      bytes = Buffer.from('reviewed input');
    await writeFile(path, bytes, { mode: 0o600 });
    const originalOpen = fs.open,
      descriptors = [],
      allocations = [];
    let changed = false;
    context.mock.method(fs, 'open', async (target, flags) => {
      const file = await originalOpen(target, flags),
        read = file.read;
      descriptors.push(file);
      context.mock.method(file, 'read', async function (...args) {
        allocations.push(args[0]);
        const result = await Reflect.apply(read, this, args);
        if (!changed) {
          changed = true;
          if (change === 'growth') await fs.appendFile(path, '\n');
          else await fs.utimes(path, 1, 1);
        }
        return result;
      });
      return file;
    });
    syncBuiltinESMExports();
    try {
      await assert.rejects(captureFile(path, bytes.length, 'Build input changed'), /changed/);
      assert.equal(changed, true);
      assert.equal(descriptors.length, 1);
      assert.equal(descriptors[0].fd, -1);
      assert.ok(allocations.every((buffer) => buffer.length <= bytes.length));
      assert.ok(allocations.every((buffer) => buffer.every((byte) => byte === 0)));
    } finally {
      context.mock.restoreAll();
      syncBuiltinESMExports();
      await Promise.all(descriptors.map((file) => file.close()));
      await rm(root, { recursive: true, force: true });
    }
  });

test('Build input capture rejects oversized files and symlinks before opening them', async (context) => {
  const root = await mkdtemp(join(tmpdir(), 'arkenivajs-capture-bounds-')),
    path = join(root, 'oversized'),
    link = join(root, 'link');
  await writeFile(path, '12345');
  await symlink(path, link);
  let opens = 0;
  const original = fs.open;
  context.mock.method(fs, 'open', (...args) => {
    opens++;
    return Reflect.apply(original, fs, args);
  });
  syncBuiltinESMExports();
  try {
    for (const target of [path, link])
      await assert.rejects(captureFile(target, 4, 'Build input rejected'), /rejected/);
    assert.equal(opens, 0);
  } finally {
    context.mock.restoreAll();
    syncBuiltinESMExports();
    await rm(root, { recursive: true, force: true });
  }
});
