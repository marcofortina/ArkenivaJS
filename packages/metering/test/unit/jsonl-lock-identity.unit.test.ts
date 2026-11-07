// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import type { BigIntStats, Stats } from 'node:fs';
import fs from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test, type TestContext } from 'node:test';
import { KitError } from '@arkenivajs/core';
import { createJsonlExporter, type MeterExporter } from '@arkenivajs/metering';
import { records } from '../fixtures/events.js';

async function lockIdentity(context: TestContext, changed?: 'ino' | 'dev') {
  const workspace = await fs.mkdtemp(join(tmpdir(), 'arkeniva-meter-wide-lock-')),
    path = join(workspace, 'events.jsonl'),
    lockPath = path + '.lock',
    displaced = join(workspace, 'original.lock'),
    base = 2n ** 53n,
    open = fs.open,
    lstat = fs.lstat;
  const handles: FileHandle[] = [];
  let exporter: MeterExporter | undefined;
  const representations: string[] = [];
  const model = (info: Stats | BigIntStats, replaced: boolean) => {
    const bigint = typeof info.ino === 'bigint';
    representations.push(bigint ? 'bigint' : 'number');
    const device = base + (replaced && changed === 'dev' ? 1n : 0n),
      inode = base + (replaced && changed === 'ino' ? 1n : 0n);
    // Only the two native identity fields are modeled; all other descriptor metadata stays real.
    return Object.defineProperties(info, {
      dev: { value: bigint ? device : Number(device) },
      ino: { value: bigint ? inode : Number(inode) },
    });
  };
  context.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    const handle = await Reflect.apply(open, fs, args);
    handles.push(handle);
    if (args[0] === lockPath) {
      const stat = handle.stat;
      context.mock.method(handle, 'stat', (async (...options: unknown[]) =>
        model(await Reflect.apply(stat, handle, options), false)) as FileHandle['stat']);
    }
    return handle;
  });
  context.mock.method(fs, 'lstat', (async (...args: unknown[]) => {
    const info = (await Reflect.apply(lstat, fs, args)) as Stats | BigIntStats;
    return args[0] === lockPath ? model(info, changed !== undefined) : info;
  }) as typeof fs.lstat);
  syncBuiltinESMExports();
  let outcome: unknown, remaining: string | undefined;
  try {
    const events = await records(1);
    exporter = await createJsonlExporter({ workspace, path: 'events.jsonl' });
    await exporter.export(events, {});
    if (changed) {
      // Keep the original inode alive so a real replacement cannot reuse its identity.
      await fs.rename(lockPath, displaced);
      await fs.writeFile(lockPath, 'foreign replacement', { mode: 0o600 });
      assert.notEqual(
        (await lstat(displaced, { bigint: true })).ino,
        (await lstat(lockPath, { bigint: true })).ino,
      );
      assert.equal(Number(base), Number(base + 1n));
    }
    outcome = await exporter.close().then(
      () => undefined,
      (error: unknown) => error,
    );
    remaining = await fs
      .readFile(lockPath, 'utf8')
      .catch((error: NodeJS.ErrnoException) => error.code);
    const observed = {
      code: outcome instanceof KitError ? outcome.code : 'none',
      remaining,
    };
    assert.deepEqual(
      observed,
      changed
        ? { code: 'EK_METER_EXPORT', remaining: 'foreign replacement' }
        : { code: 'none', remaining: 'ENOENT' },
    );
    assert.deepEqual(JSON.parse((await fs.readFile(path, 'utf8')).trim()), events[0]);
    assert.ok(handles.length >= 3);
    assert.ok(handles.every((handle) => handle.fd === -1));
  } finally {
    await exporter?.close().catch(() => undefined);
    context.diagnostic(
      JSON.stringify({
        changed: changed ?? 'none',
        code: outcome instanceof KitError ? outcome.code : 'none',
        remaining,
        representations,
        descriptorsClosed: handles.every((handle) => handle.fd === -1),
      }),
    );
    context.mock.restoreAll();
    syncBuiltinESMExports();
    await Promise.all(handles.map((handle) => handle.close()));
    await fs.rm(workspace, { recursive: true, force: true });
  }
}

test('JSONL close preserves a real foreign lock with an adjacent 64-bit inode', async (context) => {
  await lockIdentity(context, 'ino');
});

test('JSONL close preserves a real foreign lock with an adjacent 64-bit device', async (context) => {
  await lockIdentity(context, 'dev');
});

test('JSONL close releases its unchanged wide-identity lock and native descriptors', async (context) => {
  await lockIdentity(context);
});
