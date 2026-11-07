// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, access, rm, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  nativeSocket,
  prepareSocketEcho,
  socketEchoWorkload,
  completeSocketEcho,
} from '../socket-workload.mjs';

test('Socket sampling refuses unmarked execution before PKI or report allocation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-socket-entry-')),
    output = join(directory, 'report'),
    env = { ...process.env };
  delete env.ARKENIVA_SOCKET_BENCHMARK_DISPOSABLE;
  try {
    for (const mode of ['--smoke', '--smoke-unix', '--smoke-tls', '--smoke-tcp64k']) {
      await assert.rejects(
        promisify(execFile)(
          process.execPath,
          [fileURLToPath(new URL('../socket.mjs', import.meta.url)), mode, output],
          { env, timeout: 5000 },
        ),
        (cause) => {
          assert.match(cause.stderr, /Socket smoke requires an explicitly disposable/);
          return true;
        },
      );
      await assert.rejects(access(output));
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test(
  'Sampled Unix echo retains an owned mode0600 socket and retires it after incomplete evidence',
  { skip: process.platform !== 'linux' },
  async () => {
    const directory = await mkdtemp('/tmp/arkenivajs-socket-comparison-'),
      path = join(directory, 'sampled-unix4096.sock'),
      service = nativeSocket();
    try {
      await prepareSocketEcho(service, {
        directory,
        marker: 'owned-unix-sample-control',
        sampleUnixEcho: true,
      });
      const before = await lstat(path, { bigint: true });
      assert.equal(before.isSocket(), true);
      assert.equal(before.uid, BigInt(process.getuid()));
      assert.equal(before.mode & 0o777n, 0o600n);
      const callback = socketEchoWorkload(service).unix4096IndependentClient,
        running = callback();
      await assert.rejects(callback());
      const result = await running;
      assert.equal(result.receivedBytes, 4096);
      assert.equal(result.byteIdentityVerified, true);
      assert.ok(result.firstByteMs >= 0);
      assert.ok(result.exchangeElapsedMs >= result.firstByteMs);
      const current = await lstat(path, { bigint: true });
      assert.equal(current.dev, before.dev);
      assert.equal(current.ino, before.ino);
      await assert.rejects(completeSocketEcho(service, { measure: true, records: [] }));
      await assert.rejects(lstat(path), { code: 'ENOENT' });
      await assert.rejects(callback());
      assert.throws(() => socketEchoWorkload(service));
    } finally {
      await service.close();
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test('Sampled TCP echo awaits an actual independent client and rejects incomplete sample evidence', async () => {
  const service = nativeSocket();
  try {
    await prepareSocketEcho(service, { marker: 'owned-socket-sample-control' });
    await assert.rejects(prepareSocketEcho(service, { marker: 'owned-duplicate-control' }));
    const callback = socketEchoWorkload(service).tcp64IndependentClient;
    const running = callback();
    await assert.rejects(callback());
    const value = await running;
    assert.equal(value.receivedBytes, 64);
    assert.equal(value.byteIdentityVerified, true);
    assert.ok(value.firstByteMs >= 0);
    assert.ok(value.exchangeElapsedMs >= value.firstByteMs);
    await assert.rejects(completeSocketEcho(service, { measure: true, records: [] }));
    await assert.rejects(callback());
    assert.throws(() => socketEchoWorkload(service));
  } finally {
    await service.close();
  }
});

test('Sampled TCP64KiB echo verifies every byte and retires its listener after incomplete evidence', async () => {
  const service = nativeSocket();
  try {
    await prepareSocketEcho(service, {
      marker: 'owned-tcp65536-sampling-control',
      sampleTcp64kEcho: true,
    });
    const callback = socketEchoWorkload(service).tcp65536IndependentClient,
      running = callback();
    await assert.rejects(callback());
    const value = await running;
    assert.equal(value.receivedBytes, 65536);
    assert.equal(value.byteIdentityVerified, true);
    assert.ok(value.firstByteMs >= 0);
    assert.ok(value.exchangeElapsedMs >= value.firstByteMs);
    assert.equal(value.tls, undefined);
    await assert.rejects(completeSocketEcho(service, { measure: true, records: [] }));
    await assert.rejects(callback());
    assert.throws(() => socketEchoWorkload(service));
  } finally {
    await service.close();
  }
});

test('TCP64KiB sampling rejects conflicting transport selectors before opening a listener', async () => {
  const service = nativeSocket();
  try {
    for (const other of ['sampleUnixEcho', 'sampleTlsEcho'])
      await assert.rejects(
        prepareSocketEcho(service, {
          directory: '/tmp/arkenivajs-socket-comparison-unused',
          sampleTcp64kEcho: true,
          [other]: true,
        }),
      );
    assert.throws(() => socketEchoWorkload(service));
  } finally {
    await service.close();
  }
});
