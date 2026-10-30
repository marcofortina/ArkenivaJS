// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createGzip, createGunzip, gzipSync, gunzipSync } from 'node:zlib';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { zipSync, unzipSync } from 'fflate';
import { fromBufferPromise } from 'yauzl';

export const compressionFixture = Object.freeze({
  marker: 'owned-compression-fixture',
  first: 'alpha.txt',
  second: 'nested/beta.bin',
});
export const compressionSettings = Object.freeze({
  defaults: Object.freeze({}),
  policy: Object.freeze({ maxConcurrent: 1, timeoutMs: 5000 }),
});
export const payload = Buffer.from(
  Array.from(
    { length: 64 },
    (_, index) => `${compressionFixture.marker}:${index.toString().padStart(3, '0')}\n`,
  ).join(''),
);
export const entries = () => [
  { path: compressionFixture.first, data: Buffer.from(payload) },
  { path: compressionFixture.second, data: Buffer.from([0, 255, 1, 254]) },
];
export async function collect(stream) {
  const chunks = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

async function* nativeGzip(input, decode) {
  const source = Readable.from(input instanceof Uint8Array ? [input] : input, {
      objectMode: false,
      highWaterMark: 16384,
    }),
    codec = decode
      ? createGunzip({ chunkSize: 16384 })
      : createGzip({ chunkSize: 16384, level: 6 });
  const task = pipeline(source, codec);
  void task.catch(() => undefined);
  try {
    for await (const chunk of codec) yield chunk;
    await task;
  } finally {
    source.destroy();
    codec.destroy();
  }
}
/** Bare SDK operations consume a fixed finite corpus, never untrusted remote archives. */
export function nativeCompression() {
  return {
    gzip: (input) => nativeGzip(input, false),
    gunzip: (input) => nativeGzip(input, true),
    async *createZip(input) {
      const files = {};
      for await (const entry of input)
        files[entry.path] =
          entry.data instanceof Uint8Array ? entry.data : await collect(entry.data);
      yield zipSync(files, { level: 6 });
    },
    async *iterateZip(input) {
      const zip = await fromBufferPromise(
        input instanceof Uint8Array ? Buffer.from(input) : await collect(input),
        { autoClose: false, strictFileNames: true, validateEntrySizes: true },
      );
      try {
        for await (const entry of zip.eachEntry()) {
          const stream = await zip.openReadStreamPromise(entry);
          yield {
            path: entry.fileName,
            type: 'file',
            sizeBytes: entry.uncompressedSize,
            data: stream,
          };
        }
      } finally {
        zip.close();
      }
    },
  };
}

export async function archiveContents(service, archive) {
  const result = {};
  for await (const entry of service.iterateZip(archive))
    result[entry.path] = await collect(entry.data);
  return result;
}
export async function verifyCompression(service) {
  const encoded = await collect(service.gzip(payload));
  assert.deepEqual(gunzipSync(encoded), payload);
  assert.deepEqual(await collect(service.gunzip(gzipSync(payload))), payload);
  const archive = await collect(service.createZip(entries()));
  const expected = Object.fromEntries(
    entries().map((entry) => [entry.path, Buffer.from(entry.data)]),
  );
  const direct = unzipSync(archive);
  for (const [name, bytes] of Object.entries(expected))
    assert.deepEqual(Buffer.from(direct[name]), bytes);
  assert.deepEqual(await archiveContents(service, archive), expected);
  const empty = await collect(service.gzip(new Uint8Array()));
  assert.equal(gunzipSync(empty).length, 0);
  return {
    checkedGzipRoundtrips: 3,
    checkedZipEntries: 2,
    completedStreams: true,
    inputBytes: payload.byteLength,
  };
}
