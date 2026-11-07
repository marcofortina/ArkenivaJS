// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';

/** Capture one bounded regular build input without reopening its checked path. */
export async function captureFile(path, maximumBytes, message) {
  assert.ok(Number.isSafeInteger(maximumBytes) && maximumBytes > 0);
  const before = await lstat(path, { bigint: true }),
    valid = (info) => info.isFile() && info.size > 0n && info.size <= BigInt(maximumBytes),
    same = (info) =>
      ['dev', 'ino', 'size', 'mode', 'uid', 'gid', 'nlink', 'mtimeNs', 'ctimeNs'].every(
        (field) => info[field] === before[field],
      );
  assert.ok(valid(before), message);
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await file.stat({ bigint: true });
    assert.ok(valid(info) && same(info), message);
    const bytes = Buffer.alloc(Number(info.size)),
      extra = Buffer.alloc(1);
    try {
      let position = 0;
      while (position < bytes.length) {
        const { bytesRead } = await file.read(bytes, position, bytes.length - position, position);
        assert.ok(bytesRead > 0, message);
        position += bytesRead;
      }
      assert.equal((await file.read(extra, 0, 1, position)).bytesRead, 0, message);
      const after = await file.stat({ bigint: true });
      assert.ok(valid(after) && same(after), message);
      return { bytes, info };
    } catch (error) {
      bytes.fill(0);
      throw error;
    } finally {
      extra.fill(0);
    }
  } finally {
    await file.close();
  }
}
