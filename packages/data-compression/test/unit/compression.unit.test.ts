// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync, gunzipSync } from 'node:zlib';
import { randomBytes } from 'node:crypto';
import { zipSync, unzipSync, Zip, ZipPassThrough } from 'fflate';
import { setImmediate as immediate, setTimeout as delay } from 'node:timers/promises';
import { createApplication, KitError } from '@arkenivajs/core';
import { COMPRESSION_CAPABILITY, dataCompressionPlugin } from '../../dist/index.js';
import type {
  CompressionService,
  DataCompressionPluginSettings,
  OutputBytes,
} from '../../dist/index.js';

const settings = (): DataCompressionPluginSettings => ({
  defaults: {},
  policy: { maxConcurrent: 1, timeoutMs: 5000 },
});
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
async function collect(input: OutputBytes): Promise<Buffer> {
  const parts: Buffer[] = [];
  for await (const chunk of input) parts.push(Buffer.from(chunk));
  return Buffer.concat(parts);
}
async function fixture(config = settings()) {
  const app = await createApplication({
    service: { name: 'compression-tests', version: '0.1.0', environment: 'test' },
    plugins: [dataCompressionPlugin(config)],
  });
  await app.start();
  return { app, compression: app.resolve<CompressionService>(COMPRESSION_CAPABILITY) };
}
test('GZIP streams interoperate with Node and preserve binary and zero-length input', async () => {
  const { app, compression } = await fixture();
  try {
    for (const data of [Buffer.alloc(0), Buffer.from('Caffè 🦊 東京'), randomBytes(65536)]) {
      const encoded = await collect(compression.gzip(data));
      assert.deepEqual(gunzipSync(encoded), data);
      assert.deepEqual(await collect(compression.gunzip(gzipSync(data))), data);
    }
    const parts = async function* () {
      yield Buffer.from('one');
      yield new Uint8Array();
      yield Buffer.from('two');
    };
    assert.equal(gunzipSync(await collect(compression.gzip(parts()))).toString('utf8'), 'onetwo');
  } finally {
    await app.stop();
  }
});
test('ZIP creation and native central metadata iteration preserve Unicode, binary files and directories', async () => {
  const { app, compression } = await fixture();
  try {
    const binary = randomBytes(65536),
      archive = await collect(
        compression.createZip([
          { path: 'docs/', data: new Uint8Array() },
          { path: 'docs/caffè-東京.txt', data: Buffer.from('native ZIP') },
          { path: 'binary.dat', data: binary },
          { path: 'empty.txt', data: new Uint8Array() },
        ]),
      ),
      native = unzipSync(archive);
    assert.deepEqual(Buffer.from(native['binary.dat']!), binary);
    const entries: { path: string; type: string; bytes: Buffer }[] = [];
    for await (const entry of compression.iterateZip(archive))
      entries.push({ path: entry.path, type: entry.type, bytes: await collect(entry.data) });
    assert.deepEqual(
      entries.map((entry) => [entry.path, entry.type]),
      [
        ['docs/', 'directory'],
        ['docs/caffè-東京.txt', 'file'],
        ['binary.dat', 'file'],
        ['empty.txt', 'file'],
      ],
    );
    assert.deepEqual(entries[2]!.bytes, binary);
    assert.equal(entries[3]!.bytes.byteLength, 0);
    assert.equal((await collect(compression.createZip([]))).byteLength, 22);
    const empty = [];
    for await (const entry of compression.iterateZip(zipSync({}))) empty.push(entry);
    assert.deepEqual(empty, []);
  } finally {
    await app.stop();
  }
});
async function readArchive(
  compression: CompressionService,
  bytes: Uint8Array,
  options?: Parameters<CompressionService['iterateZip']>[1],
) {
  const entries = [];
  for await (const entry of compression.iterateZip(bytes, options)) entries.push(entry);
  return entries;
}
function nativeZip(
  entries: readonly { name: string; bytes?: Uint8Array; attrs?: number }[],
): Buffer {
  const output: Buffer[] = [],
    zip = new Zip((error, bytes) => {
      if (error) throw error;
      output.push(Buffer.from(bytes));
    });
  for (const entry of entries) {
    const file = new ZipPassThrough(entry.name);
    file.os = 3;
    file.attrs = entry.attrs ?? (0o100600 << 16) >>> 0;
    zip.add(file);
    file.push(entry.bytes ?? Buffer.from('fixture'), true);
  }
  zip.end();
  return Buffer.concat(output);
}
test('Both ZIP directions reject traversal, absolute paths, reserved names, collisions and symlinks', async () => {
  const { app, compression } = await fixture();
  try {
    for (const name of [
      '../escape',
      '/absolute',
      'C:/absolute',
      'a\\b',
      'a/../b',
      'a//b',
      './file',
      'NUL.txt',
      'name. ',
      'line\nname',
    ]) {
      await assert.rejects(
        collect(compression.createZip([{ path: name, data: Buffer.from('x') }])),
        code('EK_ARCHIVE_PATH'),
      );
      await assert.rejects(
        readArchive(compression, nativeZip([{ name }])),
        code('EK_ARCHIVE_PATH'),
      );
    }
    for (const names of [
      ['same', 'same'],
      ['same', 'SAME'],
      ['café', 'cafe\u0301'],
      ['a', 'a/b'],
      ['a/b', 'a'],
    ]) {
      await assert.rejects(
        collect(compression.createZip(names.map((path) => ({ path, data: Buffer.from('x') })))),
        code('EK_ARCHIVE_PATH'),
      );
      await assert.rejects(
        readArchive(compression, nativeZip(names.map((name) => ({ name })))),
        code('EK_ARCHIVE_PATH'),
      );
    }
    await assert.rejects(
      readArchive(compression, nativeZip([{ name: 'link', attrs: (0o120777 << 16) >>> 0 }])),
      code('EK_ARCHIVE_PATH'),
    );
    await assert.rejects(
      collect(compression.createZip([{ path: 'directory/', data: Buffer.from('not empty') }])),
      code('EK_ARCHIVE_PATH'),
    );
  } finally {
    await app.stop();
  }
});
test('ZIP CRC corruption is rejected before yielding any entry contents and native GZIP validates its trailer', async () => {
  const { app, compression } = await fixture();
  try {
    const archive = nativeZip([{ name: 'checksum.txt' }]),
      central = archive.indexOf(Buffer.from([80, 75, 1, 2]));
    assert.ok(central > 0);
    archive[central + 16] = archive[central + 16]! ^ 1;
    let entries = 0;
    await assert.rejects(
      (async () => {
        for await (const entry of compression.iterateZip(archive)) {
          void entry;
          entries++;
        }
      })(),
      code('EK_ARCHIVE_CORRUPT'),
    );
    assert.equal(entries, 0);
    const gzip = gzipSync(Buffer.from('checksum fixture'));
    gzip[gzip.length - 8] = gzip[gzip.length - 8]! ^ 1;
    await assert.rejects(collect(compression.gunzip(gzip)), code('EK_ARCHIVE_CORRUPT'));
    await assert.rejects(collect(compression.gunzip(new Uint8Array())), code('EK_ARCHIVE_CORRUPT'));
  } finally {
    await app.stop();
  }
});
test('Expanded bytes, entry counts/depth, compression ratios and input/output bytes have finite limits', async () => {
  const { app, compression } = await fixture();
  try {
    const bomb = Buffer.alloc(65536),
      zip = zipSync({ 'large.bin': bomb });
    await assert.rejects(readArchive(compression, zip), code('EK_ARCHIVE_LIMIT'));
    await assert.rejects(collect(compression.gunzip(gzipSync(bomb))), code('EK_ARCHIVE_LIMIT'));
    await assert.rejects(collect(compression.gzip(bomb)), code('EK_ARCHIVE_LIMIT'));
    await immediate();
    await assert.rejects(
      collect(compression.createZip([{ path: 'large.bin', data: bomb }])),
      code('EK_ARCHIVE_LIMIT'),
    );
    await assert.rejects(
      readArchive(compression, nativeZip([{ name: 'a' }, { name: 'b' }]), { maxEntries: 1 }),
      code('EK_ARCHIVE_LIMIT'),
    );
    await assert.rejects(
      readArchive(compression, nativeZip([{ name: 'a/b' }]), { maxDepth: 1 }),
      code('EK_ARCHIVE_PATH'),
    );
    await assert.rejects(
      collect(
        compression.createZip(
          [
            { path: 'a', data: Buffer.from('a') },
            { path: 'b', data: Buffer.from('b') },
          ],
          { maxEntries: 1 },
        ),
      ),
      code('EK_ARCHIVE_LIMIT'),
    );
    await assert.rejects(
      collect(compression.gzip(Buffer.from('input bound'), { maxUncompressedBytes: 1 })),
      code('EK_ARCHIVE_LIMIT'),
    );
    await assert.rejects(
      collect(compression.gzip(Buffer.from('output bound'), { maxCompressedBytes: 1 })),
      code('EK_ARCHIVE_LIMIT'),
    );
    await assert.rejects(
      readArchive(compression, zipSync({ file: Buffer.from('entry bound') }), { maxEntryBytes: 1 }),
      code('EK_ARCHIVE_LIMIT'),
    );
    await assert.rejects(
      collect(
        compression.createZip([{ path: 'file', data: Buffer.from('entry bound') }], {
          maxEntryBytes: 1,
        }),
      ),
      code('EK_ARCHIVE_LIMIT'),
    );
  } finally {
    await app.stop();
  }
});
test('Cancellation retains physical admission until an uncooperative input task actually settles', async () => {
  const { app, compression } = await fixture();
  let release!: (value: IteratorResult<Uint8Array>) => void, entered!: () => void;
  const ready = new Promise<void>((resolve) => {
      entered = resolve;
    }),
    held = new Promise<IteratorResult<Uint8Array>>((resolve) => {
      release = resolve;
    });
  let nextCalls = 0;
  const source = {
      [Symbol.asyncIterator]() {
        return {
          next() {
            nextCalls++;
            entered();
            return held;
          },
          async return() {
            return { done: true as const, value: undefined };
          },
        };
      },
    },
    controller = new AbortController();
  try {
    const running = collect(compression.gzip(source, { signal: controller.signal })),
      rejected = assert.rejects(running, code('EK_ABORTED'));
    await ready;
    await assert.rejects(
      collect(compression.gzip(Buffer.from('capacity'))),
      code('EK_ARCHIVE_LIMIT'),
    );
    controller.abort(new Error('private-abort-value'));
    await rejected;
    await assert.rejects(
      collect(compression.gzip(Buffer.from('capacity'))),
      code('EK_ARCHIVE_LIMIT'),
    );
    assert.equal(nextCalls, 1);
    release({ done: true, value: undefined });
    await immediate();
    await immediate();
    assert.equal(
      gunzipSync(await collect(compression.gzip(Buffer.from('recovered')))).toString(),
      'recovered',
    );
    const aborted = new AbortController();
    aborted.abort();
    await assert.rejects(
      collect(compression.gzip(source, { signal: aborted.signal })),
      code('EK_ABORTED'),
    );
    assert.equal(nextCalls, 1);
  } finally {
    release({ done: true, value: undefined });
    await app.stop();
  }
});
test('Deadlines and CPU budgets stop empty-input loops and slow sources without late success', async () => {
  const { app, compression } = await fixture();
  try {
    const slow = async function* () {
      await delay(20);
      yield Buffer.from('late');
    };
    await assert.rejects(collect(compression.gzip(slow(), { timeoutMs: 1 })), code('EK_TIMEOUT'));
    await delay(30);
    const empty = async function* () {
      while (true) yield new Uint8Array();
    };
    await assert.rejects(collect(compression.gzip(empty(), { timeoutMs: 5 })), code('EK_TIMEOUT'));
    await immediate();
    await immediate();
    const cpu = async function* () {
      const started = process.cpuUsage();
      while (process.cpuUsage(started).user < 5000) {
        /* Charge real bounded producer CPU. */
      }
      yield Buffer.from('cpu');
    };
    await assert.rejects(
      collect(compression.gzip(cpu(), { maxCpuTimeMs: 1 })),
      code('EK_ARCHIVE_LIMIT'),
    );
  } finally {
    await app.stop();
  }
});
test('Local header disagreement, malformed archives and truncated corpora cannot bypass the catalog', async () => {
  const { app, compression } = await fixture();
  try {
    const zip = nativeZip([{ name: 'abc' }]),
      unsafe = Buffer.from(zip);
    unsafe.write('../', 30, 'ascii');
    await assert.rejects(readArchive(compression, unsafe), code('EK_ARCHIVE_PATH'));
    const disagree = Buffer.from(zip);
    disagree.write('xyz', 30, 'ascii');
    await assert.rejects(readArchive(compression, disagree), code('EK_ARCHIVE_CORRUPT'));
    for (let length = 0; length < Math.min(zip.byteLength, 120); length += 7)
      await assert.rejects(
        readArchive(compression, zip.subarray(0, length)),
        code('EK_ARCHIVE_CORRUPT'),
      );
    assert.equal((await readArchive(compression, zip))[0]?.path, 'abc');
  } finally {
    await app.stop();
  }
});
test('Strict deployment and operation bounds reject coercion, getters and forged signals without source I/O', async () => {
  let reads = 0;
  const getter = Object.defineProperty({}, 'maxEntries', {
    get() {
      reads++;
      return 1;
    },
  });
  for (const config of [
    null,
    {},
    { defaults: getter, policy: settings().policy },
    { defaults: {}, policy: { maxConcurrent: 0, timeoutMs: 1000 } },
    { defaults: {}, policy: { maxConcurrent: 1, timeoutMs: 0 } },
    { defaults: { maxRatio: NaN }, policy: settings().policy },
    { defaults: { maxEntries: 1.5 }, policy: settings().policy },
    { defaults: {}, policy: { ...settings().policy, maxOutputBytes: 0 } },
  ])
    assert.throws(() => dataCompressionPlugin(config as never), code('EK_CONFIG_INVALID'));
  const { app, compression } = await fixture();
  const source = {
    [Symbol.asyncIterator]() {
      reads++;
      throw new Error('private-source-value');
    },
  };
  try {
    for (const options of [
      null,
      getter,
      { unknown: true },
      { timeoutMs: null },
      { timeoutMs: 0 },
      { maxEntries: 1001 },
      { maxRatio: Infinity },
      { signal: { aborted: false } },
    ])
      assert.throws(() => compression.gzip(source, options as never), code('EK_CONFIG_INVALID'));
    assert.equal(reads, 0);
    await assert.rejects(collect(compression.gzip(source)), (error) => {
      assert.ok(code('EK_ARCHIVE_CORRUPT')(error));
      assert.ok(!JSON.stringify((error as KitError).toSafeJSON()).includes('private-source-value'));
      return true;
    });
    assert.equal(reads, 1);
    for (const input of [
      null,
      {},
      'https://private.invalid/archive',
      new DataView(new ArrayBuffer(8)),
    ])
      assert.throws(() => compression.gunzip(input as never), code('EK_ARCHIVE_CORRUPT'));
    const { SharedArrayBuffer } = globalThis;
    assert.throws(
      () => compression.gzip(new Uint8Array(new SharedArrayBuffer(8))),
      code('EK_ARCHIVE_CORRUPT'),
    );
  } finally {
    await app.stop();
  }
});
test('Paused or returned streams release owned native resources and stopping one owner isolates another', async () => {
  const a = await fixture(),
    b = await fixture();
  try {
    const initial = a.compression.createZip([{ path: 'entry', data: Buffer.from('contents') }]);
    const iterator = initial[Symbol.asyncIterator]();
    assert.equal((await iterator.next()).done, false);
    await iterator.return?.();
    await immediate();
    assert.equal(
      gunzipSync(await collect(a.compression.gzip(Buffer.from('after return')))).toString(),
      'after return',
    );
    const timed = a.compression.iterateZip(nativeZip([{ name: 'entry' }]), { timeoutMs: 10 });
    const paused = timed[Symbol.asyncIterator]();
    assert.equal((await paused.next()).done, false);
    await delay(15);
    assert.equal(
      gunzipSync(await collect(a.compression.gzip(Buffer.from('after deadline')))).toString(),
      'after deadline',
    );
    await assert.rejects(paused.next(), code('EK_TIMEOUT'));
    const stopping = a.compression.createZip([
      { path: 'entry', data: Buffer.from('stop contents') },
    ]);
    const stop = stopping[Symbol.asyncIterator]();
    await stop.next();
    await a.app.stop();
    await assert.rejects(stop.next(), code('EK_RESOURCE_CLOSED'));
    await assert.rejects(
      collect(a.compression.gzip(Buffer.from('closed'))),
      code('EK_RESOURCE_CLOSED'),
    );
    assert.equal(
      gunzipSync(await collect(b.compression.gzip(Buffer.from('other owner')))).toString(),
      'other owner',
    );
  } finally {
    await a.app.stop();
    await b.app.stop();
  }
});
test('Input byte snapshots resist caller mutation and slow consumers do not drain unbounded producers', async () => {
  const { app, compression } = await fixture();
  try {
    const bytes = new Uint8Array(Buffer.from('captured input')),
      stream = compression.gzip(bytes);
    bytes.fill(0);
    assert.equal(gunzipSync(await collect(stream)).toString(), 'captured input');
    let pulls = 0;
    const source = async function* () {
      for (let index = 0; index < 1000; index++) {
        pulls++;
        yield randomBytes(16384);
      }
    };
    const iterator = compression.gzip(source())[Symbol.asyncIterator]();
    await iterator.next();
    await delay(10);
    assert.ok(pulls < 16, 'Native backpressure must bound source read-ahead');
    await iterator.return?.();
  } finally {
    await app.stop();
  }
});
