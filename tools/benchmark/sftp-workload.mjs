// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { setImmediate } from 'node:timers/promises';
import SftpClient from 'ssh2-sftp-client';
import { quote } from 'shell-quote';

export function sftpSettings(fixture) {
  assert.equal(fixture.host, '127.0.0.1');
  assert.ok(Number.isSafeInteger(fixture.port) && fixture.port > 0 && fixture.port <= 65535);
  assert.match(fixture.root, /^\/home\/transfer\/data$/);
  assert.match(fixture.fileStem, /^owned-comparison-[a-f0-9]{32}$/);
  const key = Buffer.from(fixture.encodedKey, 'base64');
  assert.ok(key.length > 0 && key.length <= 65536);
  return {
    settings: {
      connections: [
        {
          name: 'owned',
          host: fixture.host,
          port: fixture.port,
          username: fixture.username,
          privateKeyRef: 'key',
          knownHostSha256: fixture.pins,
          allowedRemoteRoots: [fixture.root],
        },
      ],
      secretProvider: {
        usage: 'test-only',
        async get(reference) {
          assert.equal(reference, 'key');
          return { bytes: key, keyVersion: 'one' };
        },
      },
      allowedCommands: { report: { executable: '/usr/bin/printf', arguments: ['%s', '{value}'] } },
      policy: { maxConcurrent: 2, timeoutMs: 10000, maxInputBytes: 262144, maxOutputBytes: 262144 },
    },
    key,
    close: () => key.fill(0),
  };
}

export async function cleanupSftp(service, fixture) {
  const client = service.files.native('owned');
  for (const suffix of ['.part', '.ready'])
    await client.delete(fixture.root + '/' + fixture.fileStem + suffix, true);
}

/** Direct pinned SDK streams, host-key verification and native command quoting on the valid corpus. */
export async function nativeSftp(fixture) {
  const owner = sftpSettings(fixture),
    client = new SftpClient();
  try {
    await client.connect({
      host: fixture.host,
      port: fixture.port,
      username: fixture.username,
      privateKey: owner.key,
      readyTimeout: 5000,
      retries: 0,
      hostVerifier: (raw) =>
        fixture.pins.includes(
          'SHA256:' + createHash('sha256').update(raw).digest('base64').replace(/=+$/, ''),
        ),
    });
  } catch {
    try {
      await client.end();
    } finally {
      owner.close();
    }
    throw new Error('The owned SFTP comparison connection failed');
  }
  const receipt = (path, bytes, hash, startedAt) => ({
    remotePath: path,
    transferredBytes: bytes,
    startedAt,
    finishedAt: new Date().toISOString(),
    sha256: hash.digest('hex'),
  });
  const service = {
    files: {
      async upload(_name, source, path) {
        const hash = createHash('sha256'),
          startedAt = new Date().toISOString();
        let bytes = 0;
        const observe = new Transform({
          transform(chunk, _encoding, done) {
            bytes += chunk.length;
            hash.update(chunk);
            done(null, chunk);
          },
        });
        await pipeline(
          Readable.from(source, { objectMode: false }),
          observe,
          client.createWriteStream(path, { flags: 'wx', mode: 0o600, highWaterMark: 65536 }),
        );
        return receipt(path, bytes, hash, startedAt);
      },
      async download(_name, path, target) {
        const hash = createHash('sha256'),
          startedAt = new Date().toISOString();
        let bytes = 0;
        await pipeline(client.createReadStream(path, { highWaterMark: 65536 }), async (source) => {
          for await (const chunk of source) {
            bytes += chunk.length;
            hash.update(chunk);
            await target(new Uint8Array(chunk));
          }
        });
        return receipt(path, bytes, hash, startedAt);
      },
      async list(_name, path) {
        return (await client.list(path)).map((entry) => ({
          path: path + '/' + entry.name,
          sizeBytes: entry.size,
          type: entry.type === 'd' ? 'directory' : entry.type === 'l' ? 'link' : 'file',
        }));
      },
      async rename(_name, source, destination) {
        assert.equal(await client.exists(destination), false);
        await client.rename(source, destination);
        return { source, destination, atomicity: 'not-guaranteed', replaced: false };
      },
      native: () => client,
    },
    commands: {
      exec(_name, command, args) {
        assert.equal(command, 'report');
        return new Promise((resolve, reject) =>
          client.client.exec(quote(['/usr/bin/printf', '%s', args.value]), (error, channel) => {
            if (error) {
              reject(new Error('The native comparison command failed'));
              return;
            }
            const stdout = [],
              stderr = [];
            let size = 0,
              exitCode = null;
            const collect = (target) => (chunk) => {
              size += chunk.length;
              if (size > 262144) {
                channel.destroy();
                reject(new Error('The native comparison command exceeded its output bound'));
              } else target.push(Buffer.from(chunk));
            };
            channel.on('data', collect(stdout));
            channel.stderr.on('data', collect(stderr));
            channel.once('exit', (code) => {
              exitCode = code;
            });
            channel.once('error', reject);
            channel.once('close', () =>
              resolve({
                exitCode,
                stdout: Buffer.concat(stdout),
                stderr: Buffer.concat(stderr),
                truncated: false,
              }),
            );
          }),
        );
      },
    },
    async close() {
      try {
        await client.end();
      } finally {
        owner.close();
      }
    },
  };
  return service;
}

export async function verifySftp(service, fixture) {
  const data = Buffer.from(fixture.marker.repeat(4096)),
    before = Buffer.from(data),
    expected = createHash('sha256').update(data).digest('hex');
  const sourcePath = fixture.root + '/' + fixture.fileStem + '.part',
    targetPath = fixture.root + '/' + fixture.fileStem + '.ready';
  const control = service.files.native('owned');
  assert.equal(await control.exists(sourcePath), false);
  assert.equal(await control.exists(targetPath), false);
  let traversals = 0;
  const source = {
    async *[Symbol.asyncIterator]() {
      assert.equal(++traversals, 1);
      for (let offset = 0; offset < data.length; offset += 8192)
        yield data.subarray(offset, offset + 8192);
    },
  };
  try {
    const upload = await service.files.upload('owned', source, sourcePath);
    assert.equal(upload.remotePath, sourcePath);
    assert.equal(upload.transferredBytes, data.length);
    assert.equal(upload.sha256, expected);
    assert.equal(traversals, 1);
    assert.deepEqual(data, before);
    const listing = await service.files.list('owned', fixture.root),
      item = listing.find((entry) => entry.path === sourcePath);
    assert.ok(item);
    assert.equal(item.type, 'file');
    assert.equal(item.sizeBytes, data.length);
    assert.deepEqual(await service.files.rename('owned', sourcePath, targetPath), {
      source: sourcePath,
      destination: targetPath,
      atomicity: 'not-guaranteed',
      replaced: false,
    });
    const after = await service.files.list('owned', fixture.root);
    assert.equal(
      after.some((entry) => entry.path === sourcePath),
      false,
    );
    assert.equal(after.find((entry) => entry.path === targetPath)?.sizeBytes, data.length);
    const chunks = [];
    let received = 0,
      active = 0;
    const download = await service.files.download('owned', targetPath, async (chunk) => {
      assert.equal(++active, 1);
      try {
        received += chunk.length;
        assert.ok(received <= 262144);
        chunks.push(Buffer.from(chunk));
        await setImmediate();
      } finally {
        active--;
      }
    });
    assert.equal(active, 0);
    assert.equal(download.remotePath, targetPath);
    assert.equal(download.transferredBytes, data.length);
    assert.equal(download.sha256, expected);
    assert.deepEqual(Buffer.concat(chunks), data);
    const command = await service.commands.exec('owned', 'report', { value: fixture.command });
    assert.equal(command.exitCode, 0);
    assert.equal(command.truncated, false);
    assert.equal(command.stderr.byteLength, 0);
    assert.equal(Buffer.from(command.stdout).toString('utf8'), fixture.command);
    return {
      actualTransferredBytes: data.length,
      sourceConsumedOnce: true,
      remoteListingVerified: true,
      renameObserved: true,
      awaitedDownloadVerified: true,
      nativeDigestsMatched: true,
      literalCommandVerified: true,
    };
  } finally {
    await cleanupSftp(service, fixture);
  }
}
