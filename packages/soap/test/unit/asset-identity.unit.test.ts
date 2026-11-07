// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { loadAssets } from '../../dist/assets.js';
import { nativeGraph } from '../../dist/backend.js';
import { contract } from '../fixture.js';

type Scenario = 'replacement' | 'wide-replacement' | 'wide-stable' | 'nanosecond-change';
async function identity(context: TestContext, scenario: Scenario) {
  const directory = await fs.mkdtemp(join(tmpdir(), 'arkenivajs-soap-identity-')),
    path = join(directory, 'inventory.wsdl'),
    replacement = join(directory, 'replacement.wsdl'),
    changed = contract.replace('quantity', 'reserved'),
    replace = scenario === 'replacement' || scenario === 'wide-replacement',
    wide = 2n ** 53n;
  await fs.writeFile(path, contract, { mode: 0o600 });
  await fs.writeFile(replacement, changed, { mode: 0o600 });
  const before = await fs.lstat(path),
    other = await fs.lstat(replacement),
    lstat = fs.lstat,
    open = fs.open;
  assert.notEqual(before.ino, other.ino);
  assert.equal(Number(wide), Number(wide + 1n));
  let replaced = false,
    reads = 0,
    descriptor: FileHandle | undefined;
  // Full-width identity and timestamp values model legal filesystem metadata, not new test options.
  context.mock.method(fs, 'lstat', (async (target: string, options: { bigint?: boolean } = {}) => {
    const value = await Reflect.apply(lstat, fs, [target, options]);
    if (target === path && scenario !== 'replacement')
      value.ino = options.bigint ? wide : Number(wide);
    return value;
  }) as typeof fs.lstat);
  context.mock.method(fs, 'open', async (target: string, flags: number) => {
    if (target !== path) return open(target, flags);
    if (replace) {
      await fs.rename(replacement, path);
      replaced = true;
    }
    descriptor = await open(target, flags);
    assert.equal((await descriptor.stat()).ino, replace ? other.ino : before.ino);
    const stat = descriptor.stat,
      read = descriptor.read;
    if (scenario !== 'replacement')
      context.mock.method(descriptor, 'stat', async function (
        this: FileHandle,
        options: { bigint?: boolean } = {},
      ) {
        const value = await Reflect.apply(stat, this, [options]),
          id = wide + (replace ? 1n : 0n);
        value.ino = options.bigint ? id : Number(id);
        if (options.bigint && scenario === 'nanosecond-change' && reads > 0) {
          assert.ok('mtimeNs' in value);
          value.mtimeNs += 1n;
        }
        return value;
      } as FileHandle['stat']);
    context.mock.method(descriptor, 'read', function (this: FileHandle, ...args: unknown[]) {
      reads++;
      return Reflect.apply(read, this, args) as ReturnType<FileHandle['read']>;
    });
    return descriptor;
  });
  syncBuiltinESMExports();
  try {
    if (scenario === 'wide-stable') {
      const assets = await loadAssets(path, new AbortController().signal);
      assert.equal(assets.documents.length, 1);
      assert.equal(assets.documents[0]?.source, contract);
      assert.ok((await nativeGraph(assets)).describeServices());
      assert.ok(reads > 0);
    } else {
      await assert.rejects(loadAssets(path, new AbortController().signal), {
        code: 'EK_SOAP_WSDL',
      });
      if (replace) assert.equal(reads, 0);
      else assert.ok(reads > 0);
    }
    assert.equal(replaced, replace);
    assert.ok(descriptor);
    assert.equal(descriptor.fd, -1);
    assert.equal(await fs.readFile(path, 'utf8'), replace ? changed : contract);
  } finally {
    context.diagnostic(
      JSON.stringify({ scenario, replaced, reads, closed: descriptor?.fd === -1 }),
    );
    context.mock.restoreAll();
    syncBuiltinESMExports();
    await descriptor?.close();
    await fs.rm(directory, { recursive: true, force: true });
  }
}

test('SOAP capture rejects a different real regular inode before reading it', (context) =>
  identity(context, 'replacement'));
test('SOAP capture rejects distinct legal 64-bit identities that collide as Numbers', (context) =>
  identity(context, 'wide-replacement'));
test('SOAP capture accepts a stable legal 64-bit identity and compiles actual native WSDL', (context) =>
  identity(context, 'wide-stable'));
test('SOAP capture rejects a one-nanosecond change even when millisecond values are unchanged', (context) =>
  identity(context, 'nanosecond-change'));
