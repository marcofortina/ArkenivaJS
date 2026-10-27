// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { randomUUID, randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import SftpClient from 'ssh2-sftp-client';
import { KitError, createApplication } from '@arkenivajs/core';
import { sftpPlugin, SFTP_CAPABILITY, SSH_CAPABILITY } from '../../dist/index.js';
import type { SftpPluginSettings, SftpService, SshService } from '../../dist/index.js';
import { managedService } from '../../dist/service.js';
import { capture } from '../../dist/settings.js';

const metadataPath = process.env.ARKENIVA_SFTP_FIXTURE;
if (!metadataPath) throw new Error('The owned OpenSSH fixture metadata path is required');
const metadata = JSON.parse(await readFile(metadataPath, 'utf8')) as {
  host: string;
  port: number;
  username: string;
  privateKeyFile: string;
  pins: string[];
  root: string;
};
const secret = await readFile(metadata.privateKeyFile),
  root = metadata.root;
const settings = (): SftpPluginSettings => ({
  connections: [
    {
      name: 'fixture',
      host: metadata.host,
      port: metadata.port,
      username: metadata.username,
      privateKeyRef: 'fixture-key',
      knownHostSha256: metadata.pins,
      allowedRemoteRoots: [root],
    },
  ],
  secretProvider: {
    async get() {
      return { bytes: secret, keyVersion: 'fixture-version' };
    },
  },
  allowedCommands: { report: { executable: '/usr/bin/printf', arguments: ['%s', '{value}'] } },
  policy: {
    maxConcurrent: 2,
    timeoutMs: 5000,
    maxInputBytes: 4 * 1024 * 1024,
    maxOutputBytes: 4 * 1024 * 1024,
  },
});
async function fixture(config = settings()) {
  const managed = managedService(capture(config), new AbortController().signal, () => true);
  await managed.init();
  return managed;
}
const path = () => root + '/test-' + randomUUID();
const source = async function* (input: Uint8Array) {
  for (let offset = 0; offset < input.length; offset += 16384)
    yield input.slice(offset, offset + 16384);
};
const code = (value: string) => (error: unknown) =>
  error instanceof KitError && error.code === value;
test('OpenSSH streams binary files with backpressure, integrity receipts, listing and a real native instance', async () => {
  const f = await fixture(),
    file = path(),
    data = randomBytes(512 * 1024),
    received: Uint8Array[] = [];
  try {
    const receipt = await f.sftp.upload('fixture', source(data), file);
    assert.equal(receipt.transferredBytes, data.length);
    const downloaded = await f.sftp.download('fixture', file, async (part) => {
      received.push(part);
      await delay(1);
    });
    assert.deepEqual(Buffer.concat(received), data);
    assert.equal(downloaded.sha256, receipt.sha256);
    assert.ok(
      (await f.sftp.list('fixture', root)).some(
        (entry) => entry.path === file && entry.type === 'file',
      ),
    );
    const native = f.sftp.native('fixture');
    assert.ok(native instanceof SftpClient);
    await assert.rejects(
      native.connect({ host: 'unapproved.invalid' }),
      code('EK_LIFECYCLE_STATE'),
    );
    await assert.rejects(native.end(), code('EK_LIFECYCLE_STATE'));
    const transport = (native as SftpClient & { client: { connect(options: object): unknown } })
      .client;
    assert.throws(
      () => transport.connect({ host: 'unapproved.invalid' }),
      code('EK_LIFECYCLE_STATE'),
    );
    await native.delete(file);
  } finally {
    await f.close();
  }
});
test('OpenSSH enforces fail-by-default overwrite and capability-proven POSIX replacement', async () => {
  const f = await fixture(),
    from = path(),
    to = path();
  try {
    await f.sftp.upload('fixture', source(Buffer.from('source')), from);
    await f.sftp.upload('fixture', source(Buffer.from('target')), to);
    await assert.rejects(
      f.sftp.upload('fixture', source(Buffer.from('forbidden')), to),
      code('EK_SFTP_TRANSFER'),
    );
    await assert.rejects(f.sftp.rename('fixture', from, to), code('EK_SFTP_TRANSFER'));
    const receipt = await f.sftp.rename('fixture', from, to, {
      overwrite: 'replace',
      requireAtomic: true,
    });
    assert.equal(receipt.atomicity, 'confirmed');
    assert.equal(receipt.replaced, true);
    const parts: Uint8Array[] = [];
    await f.sftp.download('fixture', to, async (part) => {
      parts.push(part);
    });
    assert.equal(Buffer.concat(parts).toString(), 'source');
    const native = f.sftp.native('fixture');
    assert.ok(native instanceof SftpClient);
    await native.delete(to);
  } finally {
    await f.close();
  }
});
test('OpenSSH rejects remote-root escapes, symlinks and permission failures without automatic retries', async () => {
  const f = await fixture();
  try {
    for (const remote of [
      root + '/../escape',
      root + '-lookalike/file',
      root + '/link/passwd',
      root + '/readonly/file',
    ])
      await assert.rejects(
        f.sftp.upload('fixture', source(Buffer.from('blocked')), remote),
        code('EK_SFTP_TRANSFER'),
      );
    await assert.rejects(f.sftp.list('fixture', root + '/link'), code('EK_SFTP_TRANSFER'));
    assert.ok(await f.sftp.list('fixture', root));
  } finally {
    await f.close();
  }
});
test('OpenSSH retains interrupted uploads as explicit partial outcomes and permits a fresh caller-selected connection attempt', async () => {
  const f = await fixture(),
    file = path(),
    controller = new AbortController();
  let release!: () => void, entered!: () => void;
  const hold = new Promise<void>((resolve) => {
      release = resolve;
    }),
    started = new Promise<void>((resolve) => {
      entered = resolve;
    });
  async function* input() {
    yield Buffer.from('partial');
    entered();
    await hold;
    yield Buffer.from('never sent');
  }
  try {
    const pending = f.sftp.upload('fixture', input(), file, { signal: controller.signal });
    await started;
    controller.abort();
    await assert.rejects(
      pending,
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_ABORTED' &&
        error.details?.outcome === 'unknown',
    );
    release();
    await f.close();
    const fresh = await fixture();
    try {
      const native = fresh.sftp.native('fixture');
      assert.ok(native instanceof SftpClient);
      assert.equal(await native.exists(file), '-');
      await native.delete(file);
    } finally {
      await fresh.close();
    }
  } finally {
    release();
    await f.close();
  }
});
test('OpenSSH bounds transfer bytes, preserves literal command arguments and returns confirmed command output', async () => {
  const f = await fixture(),
    file = path(),
    literal = "literal'; $(id); #";
  try {
    await assert.rejects(
      f.sftp.upload('fixture', source(Buffer.alloc(128)), file, { maxBytes: 16 }),
      code('EK_SFTP_TRANSFER'),
    );
    const result = await f.ssh.exec('fixture', 'report', { value: literal });
    assert.equal(Buffer.from(result.stdout).toString(), literal);
    assert.equal(result.exitCode, 0);
    assert.equal(result.truncated, false);
    const native = f.sftp.native('fixture');
    assert.ok(native instanceof SftpClient);
    if (await native.exists(file)) await native.delete(file);
  } finally {
    await f.close();
  }
});
test('OpenSSH integrates both public capabilities at READY and closes the owned native session on application shutdown', async () => {
  const app = await createApplication({
    service: { name: 'sftp-fixture', version: '1.0.0', environment: 'test' },
    plugins: [sftpPlugin(settings())],
  });
  await app.start();
  const sftp = app.resolve<SftpService>(SFTP_CAPABILITY),
    ssh = app.resolve<SshService>(SSH_CAPABILITY);
  assert.ok(await sftp.list('fixture', root));
  assert.equal((await ssh.exec('fixture', 'report', { value: 'ready' })).exitCode, 0);
  const native = sftp.native('fixture');
  assert.ok(native instanceof SftpClient);
  await app.stop();
  assert.throws(() => sftp.native('fixture'), code('EK_RESOURCE_CLOSED'));
});
