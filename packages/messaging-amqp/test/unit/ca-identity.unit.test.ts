// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import type { Stats, BigIntStats } from 'node:fs';
import fs from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import { createApplication, KitError } from '@arkenivajs/core';
import { amqpPlugin } from '../../dist/index.js';

const amqp = createRequire(import.meta.url)('amqplib') as typeof import('amqplib');

function wideMetadata<T extends Stats | BigIntStats>(value: T, inode: bigint): T {
  const bigint = typeof value.ino === 'bigint',
    device = 1n << 54n;
  return Object.assign(value, {
    dev: bigint ? device : Number(device),
    ino: bigint ? inode : Number(inode),
  });
}

async function startupWithCa(context: TestContext, replace: boolean, wide = false): Promise<void> {
  const directory = await fs.mkdtemp(join(tmpdir(), 'arkenivajs-amqp-ca-identity-')),
    caFile = join(directory, 'ca.pem'),
    replacement = join(directory, 'replacement.pem'),
    original = Buffer.from('original fixture trust\n'),
    changed = Buffer.from('replaced fixture trust\n');
  assert.equal(original.length, changed.length);
  await fs.writeFile(caFile, original, { mode: 0o600 });
  await fs.writeFile(replacement, changed, { mode: 0o600 });
  const before = await fs.lstat(caFile),
    other = await fs.lstat(replacement),
    open = fs.open,
    lstat = fs.lstat,
    firstInode = 1n << 53n;
  assert.equal(before.dev, other.dev);
  assert.notEqual(before.ino, other.ino);
  let replaced = false,
    reads = 0,
    nativeCalls = 0,
    descriptor: FileHandle | undefined;

  if (wide) {
    assert.notEqual(firstInode, firstInode + 1n);
    assert.equal(Number(firstInode), Number(firstInode + 1n));
    // Model legal full-width identities; all file bytes and descriptor operations remain native.
    context.mock.method(fs, 'lstat', (async (...arguments_: Parameters<typeof fs.lstat>) => {
      const value = await lstat(...arguments_);
      return arguments_[0] === caFile ? wideMetadata(value, firstInode) : value;
    }) as typeof fs.lstat);
  }

  // Replace real regular files at the open boundary; metadata and descriptor reads stay native.
  context.mock.method(fs, 'open', async (path: string, flags: number) => {
    if (path !== caFile) return open(path, flags);
    assert.equal(flags & constants.O_NOFOLLOW, constants.O_NOFOLLOW);
    assert.equal(flags & constants.O_NONBLOCK, constants.O_NONBLOCK);
    if (replace) {
      assert.equal(replaced, false);
      await fs.rename(replacement, caFile);
      replaced = true;
    }
    descriptor = await open(path, flags);
    const actual = await descriptor.stat();
    assert.equal(actual.ino, replace ? other.ino : before.ino);
    if (wide) {
      const stat = descriptor.stat.bind(descriptor);
      context.mock.method(descriptor, 'stat', (async (
        ...arguments_: Parameters<FileHandle['stat']>
      ) =>
        wideMetadata(
          await stat(...arguments_),
          firstInode + (replace ? 1n : 0n),
        )) as FileHandle['stat']);
    }
    const read = descriptor.read;
    context.mock.method(descriptor, 'read', function (this: FileHandle, ...args: unknown[]) {
      reads++;
      return Reflect.apply(read, this, args) as ReturnType<FileHandle['read']>;
    });
    return descriptor;
  });
  // Stop at the native connection boundary; this test establishes file identity, not broker delivery.
  context.mock.method(amqp, 'connect', async (_fields: unknown, options: unknown) => {
    nativeCalls++;
    const tls = options as { ca: Buffer; rejectUnauthorized: boolean; minVersion: string };
    assert.deepEqual(tls.ca, replace ? changed : original);
    assert.equal(tls.rejectUnauthorized, true);
    assert.equal(tls.minVersion, 'TLSv1.2');
    throw new Error('The synthetic native connection boundary is unavailable');
  });
  syncBuiltinESMExports();
  const uri = new URL('amqps://127.0.0.1');
  uri.username = 'fixture';
  uri.password = randomUUID();
  const app = await createApplication({
    service: { name: 'amqp-ca-identity', version: '1.0.0', environment: 'test' },
    plugins: [
      amqpPlugin({
        connections: [
          {
            name: 'events',
            connectionUriSecretRef: 'fixture-uri',
            tlsCaFile: caFile,
            maxInFlightPublishes: 1,
            maxMessageBytes: 1024,
            topology: { exchanges: [], queues: [{ name: 'fixture.events' }], bindings: [] },
          },
        ],
        resolveSecret: async () => uri.href,
      }),
    ],
  });
  try {
    await assert.rejects(
      app.start(),
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_PLUGIN_FAILED' &&
        error.cause instanceof KitError &&
        error.cause.code === 'EK_AMQP_CONNECT',
    );
    assert.equal(replaced, replace);
    if (replace) {
      assert.equal(reads, 0);
      assert.equal(nativeCalls, 0);
    } else {
      assert.ok(reads > 0);
      assert.equal(nativeCalls, 1);
    }
    assert.ok(descriptor);
    assert.equal(descriptor.fd, -1);
    assert.deepEqual(await fs.readFile(caFile), replace ? changed : original);
  } finally {
    await app.stop();
    context.diagnostic(
      JSON.stringify({ replaced, reads, nativeCalls, closed: descriptor?.fd === -1 }),
    );
    context.mock.restoreAll();
    syncBuiltinESMExports();
    await descriptor?.close();
    await fs.rm(directory, { recursive: true, force: true });
  }
}

test('Public AMQP startup rejects a different regular CA inode before reading it', async (context) => {
  await startupWithCa(context, true);
});

test('Public AMQP startup reads and closes an unchanged CA before verified native TLS setup', async (context) => {
  await startupWithCa(context, false);
});

test('Public AMQP startup distinguishes adjacent full-width CA inode identities', async (context) => {
  await startupWithCa(context, true, true);
});

test('Public AMQP startup accepts an unchanged full-width CA inode identity', async (context) => {
  await startupWithCa(context, false, true);
});
