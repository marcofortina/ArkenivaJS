// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { setImmediate } from 'node:timers/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
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

export const sftpSampleBytes = 65536;
export const sftpPressureBytes = 262144;
const observations = new WeakMap();

/** The finite synthetic corpus is never a credential or customer document. */
export function sftpCorpus(fixture, size) {
  assert.ok([sftpSampleBytes, sftpPressureBytes].includes(size));
  assert.equal(typeof fixture.marker, 'string');
  assert.ok(fixture.marker.length > 0 && fixture.marker.length <= 128);
  const data = Buffer.alloc(size);
  for (let offset = 0; offset < size; offset += 32)
    createHash('sha256')
      .update(fixture.marker)
      .update(':' + offset)
      .digest()
      .copy(data, offset);
  return data;
}

export function sftpSamplePath(fixture, pressure = false) {
  assert.match(fixture.root, /^\/home\/transfer\/data$/);
  assert.match(fixture.fileStem, /^owned-comparison-[a-f0-9]{32}$/);
  return fixture.root + '/' + fixture.fileStem + (pressure ? '.pressure' : '.sample');
}

/** Independently inspect persisted bytes through the approved native SDK outside timed calls. */
export async function inspectSftpFile(client, fixture, pressure = false) {
  const path = sftpSamplePath(fixture, pressure),
    expected = sftpCorpus(fixture, pressure ? sftpPressureBytes : sftpSampleBytes),
    metadata = await client.stat(path);
  assert.equal(metadata.isFile, true);
  assert.equal(metadata.size, expected.length);
  const stream = client.createReadStream(path, { highWaterMark: 65536 }),
    hash = createHash('sha256');
  let bytes = 0;
  try {
    for await (const part of stream) {
      assert.ok(bytes + part.length <= expected.length);
      assert.deepEqual(part, expected.subarray(bytes, bytes + part.length));
      hash.update(part);
      bytes += part.length;
    }
    assert.equal(bytes, expected.length);
    assert.equal(hash.digest('hex'), createHash('sha256').update(expected).digest('hex'));
    await waitUntil(() => stream.isClosed === true, 1000);
    return { bytes, digestVerified: true, nativeHandleClosed: true };
  } finally {
    stream.destroy();
  }
}

export async function sftpSmallDownload(
  service,
  fixture,
  expected = sftpCorpus(fixture, sftpSampleBytes),
) {
  assert.equal(expected.length, sftpSampleBytes);
  const path = sftpSamplePath(fixture),
    digest = createHash('sha256'),
    began = performance.now();
  let bytes = 0,
    callbacks = 0,
    active = 0,
    maximumDeliveredChunkBytes = 0,
    firstByteMs = null;
  const receipt = await service.files.download('owned', path, async (part) => {
    assert.equal(++active, 1);
    try {
      assert.ok(part instanceof Uint8Array && part.length > 0);
      assert.ok(bytes + part.length <= expected.length);
      firstByteMs ??= performance.now() - began;
      callbacks++;
      maximumDeliveredChunkBytes = Math.max(maximumDeliveredChunkBytes, part.length);
      assert.deepEqual(Buffer.from(part), expected.subarray(bytes, bytes + part.length));
      digest.update(part);
      bytes += part.length;
    } finally {
      active--;
    }
  });
  const elapsedMs = performance.now() - began;
  assert.equal(active, 0);
  assert.equal(bytes, expected.length);
  assert.ok(callbacks > 0 && firstByteMs !== null && firstByteMs <= elapsedMs);
  assert.equal(receipt.remotePath, path);
  assert.equal(receipt.transferredBytes, bytes);
  assert.equal(receipt.sha256, digest.digest('hex'));
  return {
    bytes,
    callbacks,
    firstByteMs,
    elapsedMs,
    bytesPerSecond: (bytes * 1000) / elapsedMs,
    maximumDeliveredChunkBytes,
    digestVerified: true,
    receiptVerified: true,
    concurrentDestinationCallbacksMaximum: 1,
  };
}

export function sftpWorkload(service, fixture) {
  assert.equal(observations.has(service), false);
  const tuning = configureSftpSmokeClient(service),
    state = [],
    expected = sftpCorpus(fixture, sftpSampleBytes);
  observations.set(service, { values: state, tuning });
  return {
    'download-validated-byte-stream': async () => {
      assert.ok(state.length < 128, 'The SFTP observation capacity is exceeded');
      const value = await sftpSmallDownload(service, fixture, expected);
      state.push(value);
      return value.bytes;
    },
  };
}

/** Apply the same documented upstream TCP setting to every measured profile, outside callbacks. */
export function configureSftpSmokeClient(service) {
  const client = service.files.native('owned');
  assert.ok(client instanceof SftpClient);
  const transport = client.client;
  assert.equal(typeof transport.setNoDelay, 'function');
  const returned = transport.setNoDelay(true);
  assert.equal(returned, transport);
  return { clientTcpNoDelay: true, documentedNativeClientReturned: returned === transport };
}

async function waitUntil(predicate, timeoutMs) {
  const began = performance.now();
  while (!predicate()) {
    assert.ok(performance.now() - began < timeoutMs, 'The owned SFTP observation timed out');
    await delay(2);
  }
}

/** Pause only the real destination; passively observe pinned SDK read-ahead, not server buffers. */
export async function sftpPressureProbe(service, fixture) {
  const client = service.files.native('owned'),
    previous = Object.getOwnPropertyDescriptor(client, 'createReadStream'),
    original = client.createReadStream,
    expected = sftpCorpus(fixture, sftpPressureBytes),
    path = sftpSamplePath(fixture, true),
    digest = createHash('sha256');
  assert.equal(typeof original, 'function');
  let stream,
    release,
    firstByteMs = null,
    bytes = 0,
    callbacks = 0,
    active = 0,
    settled = false,
    peakObservedSdkReadableQueueBytes = 0,
    maximumDeliveredChunkBytes = 0;
  const held = new Promise((resolve) => {
      release = resolve;
    }),
    began = performance.now();
  Object.defineProperty(client, 'createReadStream', {
    configurable: true,
    writable: true,
    value(...args) {
      assert.equal(this, client);
      assert.equal(args[0], path);
      assert.equal(args[1].highWaterMark, 65536);
      assert.equal(stream, undefined);
      stream = Reflect.apply(original, this, args);
      return stream;
    },
  });
  const observe = () => {
    if (!stream) return;
    assert.ok(Number.isSafeInteger(stream.bytesRead) && stream.bytesRead >= 0);
    assert.ok(Number.isSafeInteger(stream.readableLength) && stream.readableLength >= 0);
    peakObservedSdkReadableQueueBytes = Math.max(
      peakObservedSdkReadableQueueBytes,
      stream.readableLength,
    );
  };
  const task = service.files
    .download('owned', path, async (part) => {
      assert.equal(++active, 1);
      try {
        assert.ok(part instanceof Uint8Array && part.length > 0);
        assert.ok(bytes + part.length <= expected.length);
        firstByteMs ??= performance.now() - began;
        callbacks++;
        maximumDeliveredChunkBytes = Math.max(maximumDeliveredChunkBytes, part.length);
        assert.deepEqual(Buffer.from(part), expected.subarray(bytes, bytes + part.length));
        digest.update(part);
        bytes += part.length;
        if (callbacks === 1) await held;
      } finally {
        active--;
      }
    })
    .finally(() => {
      settled = true;
    });
  void task.catch(() => undefined);
  try {
    await waitUntil(() => callbacks === 1 || settled, 1500);
    assert.equal(settled, false);
    assert.equal(active, 1);
    assert.ok(stream);
    const plateauDeadline = performance.now() + 1000;
    let stable = 0,
      last = -1;
    while (stable < 3) {
      await delay(10);
      observe();
      assert.ok(
        performance.now() < plateauDeadline,
        'The real SDK did not reach a pre-EOF plateau',
      );
      assert.equal(callbacks, 1);
      assert.equal(settled, false);
      assert.ok(stream.bytesRead < expected.length, 'SDK read-ahead reached EOF before pressure');
      stable = stream.bytesRead === last && stream.readableLength > 0 ? stable + 1 : 0;
      last = stream.bytesRead;
    }
    const sdkBytesReadAtPlateau = stream.bytesRead,
      sdkReadableQueueBytesAtPlateau = stream.readableLength,
      holdBegan = performance.now();
    for (let index = 0; index < 5; index++) {
      await delay(10);
      observe();
      assert.equal(stream.bytesRead, sdkBytesReadAtPlateau);
      assert.equal(stream.readableLength, sdkReadableQueueBytesAtPlateau);
      assert.equal(callbacks, 1);
      assert.equal(active, 1);
      assert.equal(settled, false);
      assert.equal(stream.readableEnded, false);
    }
    const actualConsumerHoldMs = performance.now() - holdBegan,
      sdkBytesReadAfterHold = stream.bytesRead,
      destinationSettledDuringHold = settled,
      sdkReachedEofDuringHold = stream.bytesRead >= expected.length || stream.readableEnded;
    release();
    const receipt = await task;
    observe();
    await waitUntil(() => stream.isClosed === true, 1000);
    assert.equal(bytes, expected.length);
    assert.equal(receipt.remotePath, path);
    assert.equal(receipt.transferredBytes, bytes);
    assert.equal(receipt.sha256, digest.digest('hex'));
    assert.equal(stream.bytesRead, bytes);
    assert.equal(active, 0);
    assert.ok(callbacks > 1);
    return {
      bytes,
      callbacks,
      firstByteMs,
      elapsedMs: performance.now() - began,
      actualConsumerHoldMs,
      sdkBytesReadAtPlateau,
      sdkBytesReadAfterHold,
      sdkReadableQueueBytesAtPlateau,
      peakObservedSdkReadableQueueBytes,
      maximumDeliveredChunkBytes,
      concurrentDestinationCallbacksMaximum: 1,
      destinationSettledDuringHold,
      sdkReachedEofDuringHold,
      nativeHandleClosed: stream.isClosed,
      digestVerified: true,
      observedScope: 'client-sdk-readable-only',
      opaqueSshSocketServerBufferBytes: null,
      remoteProducerPressureEstablished: false,
    };
  } finally {
    release();
    await task.catch(() => undefined);
    try {
      if (stream) {
        stream.destroy();
        await waitUntil(() => stream.isClosed === true, 1000);
      }
    } finally {
      if (previous) Object.defineProperty(client, 'createReadStream', previous);
      else delete client.createReadStream;
      assert.equal(client.createReadStream, original);
    }
  }
}

export function summarizeSftpMeasurements(values, record) {
  assert.equal(record.operation, 'download-validated-byte-stream');
  assert.equal(record.sampleCount, 100);
  assert.equal(record.warmupIterations, 20);
  assert.equal(values.length, record.sampleCount + record.warmupIterations);
  assert.equal(record.rawLatency.values.length, record.sampleCount);
  return {
    actualCallbacks: values.length,
    warmupCallbacks: record.warmupIterations,
    measuredCallbacks: record.sampleCount,
    downloadBytes: values.reduce((total, value) => total + value.bytes, 0),
    destinationCallbacks: values.reduce((total, value) => total + value.callbacks, 0),
    measurements: values.map((value, index) => ({
      ...value,
      phase: index < record.warmupIterations ? 'warmup' : 'measured',
    })),
  };
}

export async function sftpObservations(service, { fixture, measure, records }) {
  if (!measure) return undefined;
  const state = observations.get(service);
  assert.ok(state);
  observations.delete(service);
  assert.equal(records.length, 1);
  const streams = summarizeSftpMeasurements(state.values, records[0]),
    pressure = await sftpPressureProbe(service, fixture),
    healthy = await sftpSmallDownload(service, fixture);
  assert.equal(healthy.bytes, sftpSampleBytes);
  return {
    ...state.tuning,
    streams,
    pressure,
    postProbeHealthy: true,
    uploadTimingSupported: false,
  };
}
