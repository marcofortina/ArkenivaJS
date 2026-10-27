// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { createHash } from 'node:crypto';
import ssh2 from 'ssh2';
const { Server, utils } = ssh2;
import type { Connection as ServerConnection } from 'ssh2';
import { KitError, createApplication } from '@arkenivajs/core';
import { sftpPlugin, SFTP_CAPABILITY, SSH_CAPABILITY } from '../../dist/index.js';
import { capture } from '../../dist/settings.js';
import { managedService } from '../../dist/service.js';
import { Request, operation } from '../../dist/request.js';
import { bytes } from '../../dist/connection.js';
import type { SftpPluginSettings } from '../../dist/index.js';

const code = (value: string) => (error: unknown) =>
  error instanceof KitError && error.code === value;
async function fixture() {
  const host = utils.generateKeyPairSync('ed25519'),
    user = utils.generateKeyPairSync('ed25519'),
    connections = new Set<ServerConnection>(),
    state = { auth: 0, rename: 0, command: '' };
  const key = utils.parseKey(host.private);
  if (key instanceof Error) throw key;
  const server = new Server({ hostKeys: [host.private] }, (client) => {
    connections.add(client);
    client.on('error', () => undefined);
    client.on('close', () => connections.delete(client));
    client.on('authentication', (auth) => {
      state.auth++;
      if (auth.method === 'publickey') auth.accept();
      else auth.reject();
    });
    client.on('ready', () =>
      client.on('session', (accept) => {
        const session = accept();
        session.on('sftp', (accept) => {
          const sftp = accept();
          sftp.on('error', () => undefined);
          sftp.on('LSTAT', (id, path) => {
            if (path === '/incoming/absent') sftp.status(id, 2);
            else
              sftp.attrs(id, {
                mode: path === '/incoming/source' ? 0o100600 : 0o40700,
                size: 0,
                uid: 1000,
                gid: 1000,
                atime: 1,
                mtime: 1,
              });
          });
          sftp.on('REALPATH', (id, path) =>
            sftp.name(id, [
              {
                filename: path,
                longname: path,
                attrs: { mode: 0o40700, uid: 1000, gid: 1000, size: 0, atime: 1, mtime: 1 },
              },
            ]),
          );
          sftp.on('RENAME', (id) => {
            state.rename++;
            sftp.status(id, 0);
          });
          sftp.on('OPEN', (id) => sftp.status(id, 3));
        });
        session.on('exec', (accept, _reject, info) => {
          state.command = info.command;
          const stream = accept();
          stream.on('error', () => undefined);
          stream.end(Buffer.alloc(256, 65), () => {
            stream.exit(0);
            stream.close();
          });
        });
      }),
    );
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (typeof address === 'string' || !address) throw new Error('Missing fixture address');
  const settings: SftpPluginSettings = {
    connections: [
      {
        name: 'fixture',
        host: '127.0.0.1',
        port: address.port,
        username: 'fixture',
        privateKeyRef: 'fixture-key',
        knownHostSha256: [
          'SHA256:' +
            createHash('sha256').update(key.getPublicSSH()).digest('base64').replace(/=+$/, ''),
        ],
        allowedRemoteRoots: ['/incoming'],
      },
    ],
    secretProvider: {
      async get() {
        return { bytes: Buffer.from(user.private), keyVersion: 'fixture-version' };
      },
    },
    allowedCommands: { report: { executable: '/usr/bin/printf', arguments: ['%s', '{value}'] } },
    policy: { maxConcurrent: 1, timeoutMs: 2000, maxOutputBytes: 128 },
  };
  return {
    settings,
    state,
    async close() {
      for (const client of connections) client.end();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
test('SFTP factory performs no provider or network I/O and exports distinct capabilities', () => {
  let calls = 0;
  const settings: SftpPluginSettings = {
    connections: [
      {
        name: 'fixture',
        host: '127.0.0.1',
        port: 9,
        username: 'fixture',
        privateKeyRef: 'key',
        knownHostSha256: ['SHA256:' + Buffer.alloc(32).toString('base64').replace(/=+$/, '')],
        allowedRemoteRoots: ['/incoming'],
      },
    ],
    secretProvider: {
      async get() {
        calls++;
        throw new Error('Unavailable');
      },
    },
    policy: { maxConcurrent: 1, timeoutMs: 100 },
  };
  assert.ok(sftpPlugin(settings).capabilities.has('sftp'));
  assert.notEqual(SFTP_CAPABILITY, SSH_CAPABILITY);
  assert.equal(calls, 0);
});
test('Host spoofing fails pin verification before any authentication is attempted', async () => {
  const f = await fixture(),
    settings = {
      ...f.settings,
      connections: [
        {
          ...f.settings.connections[0]!,
          knownHostSha256: ['SHA256:' + Buffer.alloc(32).toString('base64').replace(/=+$/, '')],
        },
      ],
    },
    managed = managedService(capture(settings), new AbortController().signal, () => true);
  try {
    await assert.rejects(managed.init(), code('EK_SFTP_HOSTKEY'));
    assert.equal(f.state.auth, 0);
  } finally {
    await managed.close();
    await f.close();
  }
});
test('Non-atomic servers reject required atomic or replacement renames before mutation', async () => {
  const f = await fixture(),
    managed = managedService(capture(f.settings), new AbortController().signal, () => true);
  try {
    await managed.init();
    await assert.rejects(
      managed.sftp.rename('fixture', '/incoming/source', '/incoming/absent', {
        requireAtomic: true,
      }),
      code('EK_UNSUPPORTED_CAPABILITY'),
    );
    assert.equal(f.state.rename, 0);
    await assert.rejects(
      managed.sftp.rename('fixture', '/incoming/source', '/incoming/absent', {
        overwrite: 'replace',
      }),
      code('EK_UNSUPPORTED_CAPABILITY'),
    );
    assert.equal(f.state.rename, 0);
    const receipt = await managed.sftp.rename('fixture', '/incoming/source', '/incoming/absent');
    assert.equal(receipt.atomicity, 'not-guaranteed');
    assert.equal(f.state.rename, 1);
  } finally {
    await managed.close();
    await f.close();
  }
});
test('SSH command arguments remain shell literals and output truncation never reports a confirmed zero exit', async () => {
  const f = await fixture(),
    managed = managedService(capture(f.settings), new AbortController().signal, () => true);
  try {
    await managed.init();
    await assert.rejects(managed.ssh.exec('fixture', 'unknown', {}), code('EK_SSH_FORBIDDEN'));
    await assert.rejects(managed.ssh.exec('fixture', 'report', { value: 'x', extra: 'x' }));
    const receipt = await managed.ssh.exec('fixture', 'report', { value: 'literal; $(id)' });
    assert.equal(receipt.stdout.length + receipt.stderr.length, 128);
    assert.equal(receipt.truncated, true);
    assert.equal(receipt.exitCode, null);
    assert.match(f.state.command, /'literal; \$\(id\)'/);
  } finally {
    await managed.close();
    await f.close();
  }
});
test('A native permission error settles queued writes and releases the owned connection', async () => {
  const f = await fixture(),
    managed = managedService(capture(f.settings), new AbortController().signal, () => true);
  try {
    await managed.init();
    async function* source() {
      yield Buffer.from('blocked');
    }
    await assert.rejects(
      managed.sftp.upload('fixture', source(), '/incoming/absent'),
      code('EK_SFTP_TRANSFER'),
    );
  } finally {
    await managed.close();
    await f.close();
  }
});
test('Cancellation returns promptly while provider work retains admission and shutdown ownership', async () => {
  const f = await fixture();
  let release!: () => void, entered!: () => void;
  const hold = new Promise<void>((resolve) => {
      release = resolve;
    }),
    started = new Promise<void>((resolve) => {
      entered = resolve;
    });
  const managed = managedService(
      capture({
        ...f.settings,
        secretProvider: {
          async get(reference, options) {
            entered();
            await hold;
            return f.settings.secretProvider.get(reference, options);
          },
        },
      }),
      new AbortController().signal,
      () => true,
    ),
    controller = new AbortController();
  const pending = managed.sftp.list('fixture', '/incoming', { signal: controller.signal });
  await started;
  controller.abort();
  await assert.rejects(pending, code('EK_ABORTED'));
  await assert.rejects(managed.sftp.list('fixture', '/incoming'), code('EK_SFTP_TRANSFER'));
  let drained = false;
  const closing = managed.close().then(() => {
    drained = true;
  });
  await delay(15);
  assert.equal(drained, false);
  release();
  await closing;
  assert.equal(drained, true);
  await f.close();
});
test('Request validation rejects zero timeouts, forged signals and shared secret buffers', () => {
  for (const value of [0, -1, 1.5, NaN, Infinity])
    assert.throws(() => operation({ timeoutMs: value }, 100));
  assert.throws(() => operation({ signal: { aborted: false } as AbortSignal }, 100));
  assert.throws(() => bytes(new Uint8Array(new SharedArrayBuffer(16)), 32));
  assert.deepEqual(bytes(Uint8Array.of(1, 2), 2), Buffer.from([1, 2]));
});
test('Readiness, closed native handles and test-only providers fail closed before provider I/O', async () => {
  const f = await fixture();
  let calls = 0;
  const provider = Object.assign(Object.create({ usage: 'test-only' }) as object, {
      async get() {
        calls++;
        throw new Error('Must not execute');
      },
    }),
    settings = { ...f.settings, secretProvider: provider as SftpPluginSettings['secretProvider'] },
    managed = managedService(capture(settings), new AbortController().signal, () => false);
  try {
    await assert.rejects(managed.sftp.list('fixture', '/incoming'), code('EK_LIFECYCLE_STATE'));
    const app = await createApplication({
      service: { name: 'sftp-production', version: '1.0.0', environment: 'production' },
      plugins: [sftpPlugin(settings)],
    });
    try {
      await assert.rejects(
        app.start(),
        (error: unknown) =>
          error instanceof KitError &&
          error.code === 'EK_PLUGIN_FAILED' &&
          error.cause instanceof KitError &&
          error.cause.code === 'EK_CONFIG_INVALID',
      );
    } finally {
      await app.stop();
    }
    assert.equal(calls, 0);
    await managed.close();
    assert.throws(() => managed.sftp.native('fixture'), code('EK_RESOURCE_CLOSED'));
  } finally {
    await managed.close();
    await f.close();
  }
});
test('Invalid or unavailable secrets are sanitized and never modify provider-owned key buffers', async () => {
  const f = await fixture(),
    original = Buffer.from('unavailable-private-material');
  for (const value of [
    undefined,
    { bytes: original, keyVersion: '' },
    { bytes: original, keyVersion: 'fixture-version', expiresAt: 'invalid' },
    { bytes: original, keyVersion: 'fixture-version', expiresAt: '2000-01-01T00:00:00Z' },
    { bytes: new Uint8Array(new SharedArrayBuffer(32)), keyVersion: 'fixture-version' },
  ]) {
    const managed = managedService(
      capture({
        ...f.settings,
        secretProvider: {
          async get() {
            if (!value) throw new Error(original.toString());
            return value;
          },
        },
      }),
      new AbortController().signal,
      () => true,
    );
    try {
      await assert.rejects(
        managed.init(),
        (error: unknown) =>
          error instanceof KitError &&
          error.code === 'EK_SFTP_TRANSFER' &&
          !error.message.includes(original.toString()),
      );
    } finally {
      await managed.close();
    }
  }
  assert.equal(original.toString(), 'unavailable-private-material');
  await f.close();
});
test('A timed-out request acknowledges retained application work before releasing its done promise', async () => {
  let release!: () => void;
  const hold = new Promise<void>((resolve) => {
      release = resolve;
    }),
    request = new Request(
      10,
      undefined,
      new AbortController().signal,
      () => undefined,
      async () => {
        await hold;
        return true;
      },
    );
  await assert.rejects(request.result, code('EK_TIMEOUT'));
  let done = false;
  void request.done.then(() => {
    done = true;
  });
  await delay(10);
  assert.equal(done, false);
  release();
  await request.done;
  assert.equal(done, true);
});
