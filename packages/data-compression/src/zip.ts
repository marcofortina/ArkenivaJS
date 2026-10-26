// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { crc32 } from 'node:zlib';
import { Zip, ZipDeflate } from 'fflate';
import { fromBufferPromise, getFileNameLowLevel, parseExtraFields } from 'yauzl';
import { isUtf8 } from 'node:buffer';
import type { Entry } from 'yauzl';
import { chunks, Runtime } from './runtime.js';
import { failure, safeFailure, fields, path, register, source } from './settings.js';
import type { Policy } from './settings.js';
import type { ArchiveEntry, ArchiveInputEntry, InputBytes, OutputBytes } from './contracts.js';

/** fflate encodes ZIP bytes; the wrapper only gates names, accounting and native callbacks. */
export async function* createZip(
  input: Iterable<ArchiveInputEntry> | AsyncIterable<ArchiveInputEntry>,
  policy: Policy,
  runtime: Runtime,
): OutputBytes {
  const lease = runtime.acquire(policy, 'create_zip'),
    names = new Map<string, boolean>(),
    pending: Uint8Array[] = [],
    inputLimit = Math.min(runtime.settings.maxInputBytes, policy.maxUncompressedBytes),
    outputLimit = Math.min(runtime.settings.maxOutputBytes, policy.maxCompressedBytes);
  let error: unknown,
    ended = false,
    compressed = 0,
    expanded = 0;
  const zip = new Zip((cause, output, final) => {
    if (cause) {
      error = cause;
      return;
    }
    compressed += output.byteLength;
    lease.account(compressed, expanded);
    if (compressed > outputLimit) {
      error = failure('EK_ARCHIVE_LIMIT');
      return;
    }
    pending.push(output);
    ended = final;
  });
  lease.cleanup(() => {
    zip.terminate();
    pending.length = 0;
  });
  try {
    const iterator =
      Symbol.asyncIterator in input ? input[Symbol.asyncIterator]() : input[Symbol.iterator]();
    let inputEnded = false;
    lease.cleanup(() => {
      if (!inputEnded && iterator.return) {
        inputEnded = true;
        lease.track(Promise.resolve().then(() => iterator.return!()));
      }
    });
    const check = () => {
      lease.check();
      if (error) throw safeFailure(error);
    };
    while (true) {
      check();
      const next = await lease.wait(
        Promise.resolve().then(() => {
          lease.check();
          return iterator.next();
        }),
      );
      if (next.done) {
        inputEnded = true;
        break;
      }
      if (names.size >= policy.maxEntries) throw failure('EK_ARCHIVE_LIMIT');
      const value = fields(next.value, ['path', 'data']),
        name = path(value.path, policy.maxDepth);
      register(names, name);
      const data = source(value.data as InputBytes, inputLimit),
        file = new ZipDeflate(name.name, { level: 6 });
      file.os = 3;
      file.attrs = ((name.directory ? 0o40700 : 0o100600) << 16) >>> 0;
      zip.add(file);
      let entryBytes = 0,
        entryCompressed = 0;
      const native = file.ondata;
      file.ondata = (cause, output, final) => {
        if (output) entryCompressed += output.byteLength;
        native(cause, output, final);
      };
      while (pending.length) {
        check();
        yield new Uint8Array(pending.shift()!);
      }
      for await (const chunk of chunks(data, lease, Math.min(policy.maxEntryBytes, inputLimit))) {
        entryBytes += chunk.byteLength;
        expanded += chunk.byteLength;
        lease.account(compressed, expanded);
        if (expanded > inputLimit || (name.directory && entryBytes > 0))
          throw failure(name.directory ? 'EK_ARCHIVE_PATH' : 'EK_ARCHIVE_LIMIT');
        check();
        file.push(chunk, false);
        while (pending.length) {
          check();
          yield new Uint8Array(pending.shift()!);
        }
      }
      check();
      file.push(new Uint8Array(), true);
      check();
      if (entryBytes > Math.max(1, entryCompressed) * policy.maxRatio)
        throw failure('EK_ARCHIVE_LIMIT');
      while (pending.length) {
        check();
        yield new Uint8Array(pending.shift()!);
      }
    }
    zip.end();
    check();
    if (!ended || expanded > Math.max(1, compressed) * policy.maxRatio)
      throw failure('EK_ARCHIVE_CORRUPT');
    while (pending.length) {
      check();
      yield new Uint8Array(pending.shift()!);
    }
    lease.success();
  } catch (cause) {
    lease.check();
    throw lease.fail(cause);
  } finally {
    lease.finish();
  }
}

/** Parse central metadata through yauzl; CRC32 is the native Node implementation. */
export async function* iterateZip(
  input: InputBytes,
  policy: Policy,
  runtime: Runtime,
): AsyncIterable<ArchiveEntry> {
  const lease = runtime.acquire(policy, 'iterate_zip'),
    inputLimit = Math.min(policy.maxCompressedBytes, runtime.settings.maxInputBytes),
    outputLimit = Math.min(policy.maxUncompressedBytes, runtime.settings.maxOutputBytes),
    buffers: Buffer[] = [];
  let compressed = 0,
    expanded = 0;
  try {
    for await (const chunk of chunks(input, lease, inputLimit)) {
      compressed += chunk.byteLength;
      lease.account(compressed, expanded);
      buffers.push(Buffer.from(chunk));
    }
    const archive = Buffer.concat(buffers);
    buffers.length = 0;
    const zip = await lease.wait(
      fromBufferPromise(archive, {
        autoClose: false,
        strictFileNames: true,
        validateEntrySizes: true,
        decodeStrings: false,
      }),
    );
    zip.on('error', () => undefined);
    lease.cleanup(() => zip.close());
    if (zip.entryCount > policy.maxEntries) throw failure('EK_ARCHIVE_LIMIT');
    const names = new Map<string, boolean>(),
      catalog: { native: Entry; name: ReturnType<typeof path> }[] = [],
      iterator = zip.eachEntry();
    let declared = 0;
    while (true) {
      const next = await lease.wait(iterator.next());
      if (next.done) break;
      if (catalog.length >= policy.maxEntries) throw failure('EK_ARCHIVE_LIMIT');
      const entry = next.value;
      if (entry.fileNameRaw.some((byte) => byte < 32 || byte === 127))
        throw failure('EK_ARCHIVE_PATH');
      if ((entry.generalPurposeBitFlag & 0x800) !== 0 && !isUtf8(entry.fileNameRaw))
        throw failure('EK_ARCHIVE_PATH');
      const name = path(
          getFileNameLowLevel(
            entry.generalPurposeBitFlag,
            entry.fileNameRaw,
            entry.extraFields,
            true,
          ),
          policy.maxDepth,
        ),
        mode = (entry.externalFileAttributes >>> 16) & 0o170000;
      register(names, name);
      if (
        (mode !== 0 && mode !== (name.directory ? 0o040000 : 0o100000)) ||
        ((entry.externalFileAttributes & 16) !== 0 && !name.directory)
      )
        throw failure('EK_ARCHIVE_PATH');
      if (!entry.canDecodeFileData() || entry.isEncrypted()) throw failure('EK_ARCHIVE_CORRUPT');
      if (
        ![entry.compressedSize, entry.uncompressedSize].every(
          (size) => Number.isSafeInteger(size) && size >= 0,
        )
      )
        throw failure('EK_ARCHIVE_CORRUPT');
      declared += entry.uncompressedSize;
      if (
        declared > outputLimit ||
        entry.uncompressedSize > policy.maxEntryBytes ||
        entry.uncompressedSize > Math.max(1, entry.compressedSize) * policy.maxRatio
      )
        throw failure('EK_ARCHIVE_LIMIT');
      if (name.directory && entry.uncompressedSize !== 0) throw failure('EK_ARCHIVE_PATH');
      const local = await lease.wait(zip.readLocalFileHeaderPromise(entry));
      if (local.fileName.some((byte) => byte < 32 || byte === 127))
        throw failure('EK_ARCHIVE_PATH');
      path(
        getFileNameLowLevel(
          local.generalPurposeBitFlag,
          local.fileName,
          parseExtraFields(local.extraField),
          true,
        ),
        policy.maxDepth,
      );
      if (
        !local.fileName.equals(entry.fileNameRaw) ||
        local.compressionMethod !== entry.compressionMethod ||
        local.generalPurposeBitFlag !== entry.generalPurposeBitFlag
      )
        throw failure('EK_ARCHIVE_CORRUPT');
      catalog.push({ native: entry, name });
    }
    for (const entry of catalog) {
      lease.check();
      const stream = await lease.wait(zip.openReadStreamPromise(entry.native));
      stream.on('error', () => undefined);
      const closed = lease.track(
        new Promise<void>((resolve) => {
          stream.once('close', resolve);
        }),
      );
      lease.cleanup(() => stream.destroy());
      const pieces: Uint8Array[] = [],
        iterator = stream[Symbol.asyncIterator]();
      let length = 0,
        crc = 0;
      while (true) {
        const next = await lease.wait(iterator.next());
        if (next.done) break;
        const chunk = new Uint8Array(next.value as Buffer);
        length += chunk.byteLength;
        expanded += chunk.byteLength;
        lease.account(compressed, expanded);
        if (
          length > policy.maxEntryBytes ||
          expanded > outputLimit ||
          length > entry.native.uncompressedSize ||
          length > Math.max(1, entry.native.compressedSize) * policy.maxRatio
        )
          throw failure('EK_ARCHIVE_LIMIT');
        crc = crc32(chunk, crc);
        pieces.push(chunk);
      }
      await lease.wait(closed);
      if (crc !== entry.native.crc32 || length !== entry.native.uncompressedSize)
        throw failure('EK_ARCHIVE_CORRUPT');
      const bytes = new Uint8Array(Buffer.concat(pieces)),
        result = Object.freeze({
          path: entry.name.name,
          type: entry.name.directory ? ('directory' as const) : ('file' as const),
          sizeBytes: length,
          data: (async function* () {
            for (let offset = 0; offset < bytes.byteLength; offset += 16384)
              yield bytes.slice(offset, offset + 16384);
          })(),
        });
      lease.check();
      yield result;
    }
    if (expanded > Math.max(1, compressed) * policy.maxRatio) throw failure('EK_ARCHIVE_LIMIT');
    lease.success();
  } catch (cause) {
    lease.check();
    throw lease.fail(cause);
  } finally {
    buffers.length = 0;
    lease.finish();
  }
}
