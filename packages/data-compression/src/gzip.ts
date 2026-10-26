// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createGzip, createGunzip } from 'node:zlib';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { failure } from './settings.js';
import type { Policy } from './settings.js';
import type { InputBytes, OutputBytes } from './contracts.js';
import { chunks, Runtime } from './runtime.js';

/** Native streaming codecs own their input pipeline and never acknowledge expired output. */
export async function* gzip(
  input: InputBytes,
  policy: Policy,
  runtime: Runtime,
  decode: boolean,
): OutputBytes {
  const lease = runtime.acquire(policy, decode ? 'gunzip' : 'gzip'),
    inputLimit = Math.min(
      runtime.settings.maxInputBytes,
      decode ? policy.maxCompressedBytes : policy.maxUncompressedBytes,
    ),
    outputLimit = Math.min(
      runtime.settings.maxOutputBytes,
      decode ? policy.maxUncompressedBytes : policy.maxCompressedBytes,
    );
  let inputBytes = 0,
    outputBytes = 0;
  const measured = async function* () {
      for await (const chunk of chunks(input, lease, inputLimit)) {
        inputBytes += chunk.byteLength;
        lease.account(decode ? inputBytes : outputBytes, decode ? outputBytes : inputBytes);
        yield chunk;
      }
    },
    source = Readable.from(measured(), { objectMode: false, highWaterMark: 16384 }),
    codec = decode
      ? createGunzip({ chunkSize: 16384 })
      : createGzip({ chunkSize: 16384, level: 6 });
  // Observe native errors from birth, including errors before the output iterator starts.
  codec.on('error', () => undefined);
  source.on('error', () => undefined);
  lease.cleanup(() => {
    source.destroy();
    codec.destroy();
  });
  const task = lease.track(pipeline(source, codec, { signal: lease.signal }));
  try {
    for await (const output of codec) {
      lease.check();
      outputBytes += output.byteLength;
      lease.account(decode ? inputBytes : outputBytes, decode ? outputBytes : inputBytes);
      if (
        outputBytes > outputLimit ||
        (decode && outputBytes > Math.max(1, inputBytes) * policy.maxRatio)
      )
        throw failure('EK_ARCHIVE_LIMIT');
      yield new Uint8Array(output);
    }
    await lease.wait(task);
    if (!decode && inputBytes > Math.max(1, outputBytes) * policy.maxRatio)
      throw failure('EK_ARCHIVE_LIMIT');
    lease.success();
  } catch (cause) {
    lease.check();
    throw lease.fail(cause);
  } finally {
    lease.finish();
  }
}
