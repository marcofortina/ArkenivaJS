// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { constants } from 'node:fs';
import { lstat, realpath, open, unlink } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { InputBytes } from './contracts.js';
import type { Options } from './settings.js';
import type { Scope } from './runtime.js';
import { bytes, failure } from './validation.js';

/** Only an explicit, private, application-owned directory permits one-shot random-access staging. */
export async function input(
  source: InputBytes,
  policy: Options,
  scope: Scope,
): Promise<{
  readonly data?: Buffer;
  readonly path?: string;
  cleanup(): Promise<void>;
}> {
  const maximum = Math.min(scope.book.settings.maxInputBytes, policy.maxUncompressedBytes);
  if (source instanceof Uint8Array) {
    const data = bytes(source, maximum);
    scope.book.observe?.measure('input.bytes', data.length);
    return {
      data,
      async cleanup() {
        data.fill(0);
      },
    };
  }
  if (!source || typeof source[Symbol.asyncIterator] !== 'function') throw failure();
  const storage = policy.temporaryStorage,
    staging = policy.readMode === 'random-access';
  if (staging && !storage) throw failure('EK_XLSX_UNSUPPORTED');
  let file: FileHandle | undefined,
    path: string | undefined,
    total = 0;
  const chunks: Buffer[] = [];
  let iterator: AsyncIterator<Uint8Array> | undefined;
  const cleanup = async () => {
    await file?.close();
    file = undefined;
    for (const chunk of chunks) chunk.fill(0);
    chunks.length = 0;
    if (path) {
      const owned = path;
      path = undefined;
      await unlink(owned);
    }
  };
  try {
    if (staging && storage) {
      const root = resolve(storage.directory),
        actual = await realpath(root),
        stat = await lstat(root);
      scope.check();
      if (
        actual !== root ||
        !stat.isDirectory() ||
        stat.isSymbolicLink() ||
        typeof process.getuid !== 'function' ||
        stat.uid !== process.getuid() ||
        (stat.mode & 0o077) !== 0
      )
        throw failure('EK_XLSX_UNSUPPORTED');
      const candidate = join(root, 'arkenivajs-xlsx-' + randomUUID());
      file = await open(
        candidate,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
        0o600,
      );
      path = candidate;
    }
    iterator = source[Symbol.asyncIterator]();
    if (!iterator || typeof iterator.next !== 'function') throw failure();
    for (;;) {
      scope.check();
      const next = await scope.wait(Promise.resolve(iterator.next()));
      if (next.done) break;
      const chunk = bytes(next.value, maximum - total);
      try {
        total += chunk.length;
        if (total > maximum || (staging && total > storage!.maxBytes))
          throw failure('EK_XLSX_LIMIT');
        if (file) {
          let written = 0;
          while (written < chunk.length) {
            scope.check();
            const result = await scope.wait(file.write(chunk, written, chunk.length - written));
            if (result.bytesWritten <= 0) throw failure();
            written += result.bytesWritten;
          }
        } else chunks.push(Buffer.from(chunk));
      } finally {
        chunk.fill(0);
      }
    }
    if (!total) throw failure();
    scope.book.observe?.measure('input.bytes', total);
    await file?.close();
    file = undefined;
    if (path) {
      const stagedPath = path;
      return { path: stagedPath, cleanup };
    }
    const data = Buffer.concat(chunks);
    await cleanup();
    return {
      data,
      async cleanup() {
        data.fill(0);
      },
    };
  } catch (error) {
    if (iterator?.return) {
      try {
        scope.book.track(Promise.resolve(iterator.return()));
      } catch {
        /* Retain the original failure. */
      }
    }
    await cleanup();
    throw error;
  }
}
