// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, rm, symlink, truncate, open } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { readIdeAssets } from '../../dist/ide.js';

const digest = (content: string | Buffer) => createHash('sha256').update(content).digest('hex');
async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-ide-assets-'));
  await mkdir(join(directory, 'assets'));
  const js = 'export {};',
    css = 'body{}';
  await writeFile(join(directory, 'assets/app.js'), js);
  await writeFile(join(directory, 'assets/app.css'), css);
  const files = [
    { name: 'app.js', bytes: Buffer.byteLength(js), sha256: digest(js) },
    { name: 'app.css', bytes: Buffer.byteLength(css), sha256: digest(css) },
  ];
  const manifest = (value: unknown) =>
    writeFile(join(directory, 'manifest.json'), JSON.stringify(value));
  await manifest({ format: 1, files });
  return {
    directory,
    files,
    manifest,
    read: () => readIdeAssets(pathToFileURL(directory + '/')),
    close: () => rm(directory, { recursive: true, force: true }),
  };
}

test('IDE artifact reader accepts exact entry points and denies malformed or unbounded manifest structure', async () => {
  const f = await fixture();
  try {
    const accepted = await f.read();
    assert.equal(accepted.get('app.js')?.content.toString(), 'export {};');
    assert.equal(accepted.get('app.css')?.mime, 'text/css');
    for (const value of [
      null,
      false,
      1,
      'invalid',
      [],
      {},
      { format: 2, files: f.files },
      { format: 1 },
      { format: 1, files: {} },
      { format: 1, files: [] },
      { format: 1, files: Array(1001).fill(f.files[0]) },
    ]) {
      await f.manifest(value);
      await assert.rejects(f.read(), { code: 'EK_GQL_CONFIG' });
    }
    for (const bytes of [Buffer.from('{broken'), Buffer.from([0xc0, 0xaf])]) {
      await writeFile(join(f.directory, 'manifest.json'), bytes);
      await assert.rejects(f.read(), { code: 'EK_GQL_CONFIG' });
    }
    await truncate(join(f.directory, 'manifest.json'), 1048577);
    await assert.rejects(f.read(), { code: 'EK_GQL_CONFIG' });
  } finally {
    await f.close();
  }
});

test('IDE asset declarations reject traversal, duplicate entries, invalid sizes and mismatched hashes', async () => {
  const f = await fixture();
  try {
    const good = f.files[0]!;
    for (const entry of [
      null,
      1,
      {},
      { ...good, name: 1 },
      ...['../app.js', '/app.js', 'app.svg', 'a'.repeat(129) + '.js'].map((name) => ({
        ...good,
        name,
      })),
      ...[-1, 0.5, false, 33554433].map((bytes) => ({ ...good, bytes })),
      { ...good, sha256: false },
      { ...good, sha256: 'wrong' },
      { ...good, sha256: '0'.repeat(64) },
      { ...good, bytes: good.bytes + 1 },
    ]) {
      await f.manifest({ format: 1, files: [entry, f.files[1]] });
      await assert.rejects(f.read(), { code: 'EK_GQL_CONFIG' });
    }
    for (const files of [[f.files[0], f.files[0], f.files[1]], [f.files[0]], [f.files[1]]]) {
      await f.manifest({ format: 1, files });
      await assert.rejects(f.read(), { code: 'EK_GQL_CONFIG' });
    }
  } finally {
    await f.close();
  }
});

test('IDE reads reject oversized physical files, links and directories without trusting declared length', async () => {
  const f = await fixture();
  try {
    const path = join(f.directory, 'assets/app.js');
    await truncate(path, 33554433);
    await assert.rejects(f.read(), { code: 'EK_GQL_CONFIG' });
    await rm(path);
    await writeFile(join(f.directory, 'outside.js'), 'export {};');
    await symlink(join(f.directory, 'outside.js'), path);
    await assert.rejects(f.read(), { code: 'EK_GQL_CONFIG' });
    await rm(path);
    await mkdir(path);
    await assert.rejects(f.read(), { code: 'EK_GQL_CONFIG' });
    await rm(path, { recursive: true });
    await assert.rejects(f.read(), { code: 'EK_GQL_CONFIG' });
  } finally {
    await f.close();
  }
});

test('IDE aggregate assets cannot exceed 64 MiB even when individual files and hashes are valid', async () => {
  const f = await fixture();
  try {
    const size = 22 * 1024 * 1024,
      sha256 = digest(Buffer.alloc(size));
    const files = ['app.js', 'app.css', 'other.js'].map((name) => ({ name, bytes: size, sha256 }));
    for (const file of files) {
      const handle = await open(join(f.directory, 'assets', file.name), 'w');
      try {
        await handle.truncate(size);
      } finally {
        await handle.close();
      }
    }
    await f.manifest({ format: 1, files });
    await assert.rejects(f.read(), { code: 'EK_GQL_CONFIG' });
  } finally {
    await f.close();
  }
});
